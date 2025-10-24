# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyVPN is an educational VPN implementation in Python for learning networking fundamentals. It consists of:
- **Client** (`vpn_client.py`): macOS VPN client using TUN interfaces
- **Server** (`vpn_server.py`): Linux VPN server for AWS EC2 deployment
- **Infrastructure** (`app.py`, `deploy.py`): AWS CDK deployment automation

The VPN uses AES-256-GCM encryption with PBKDF2 key derivation from a shared password. All traffic is tunneled over UDP (default port 51820).

## Coding Standards

**See [STYLE_GUIDE.md](STYLE_GUIDE.md) for comprehensive coding standards.**

Key conventions:
- **Package management**: ALWAYS use `uv` (never pip, requirements.txt, or manual virtualenv)
- **Python style**: PEP 8, snake_case for functions/variables, PascalCase for classes
- **Type hints**: Use for function signatures, skip for obvious cases
- **Error handling**: Specific exceptions with helpful messages, never bare `except`
- **Output symbols**: ✓ (success), ✗ (error), → (outgoing), ← (incoming), ⚠️ (warning)
- **Documentation**: Docstrings for public APIs, comments explain WHY not WHAT
- **Resource cleanup**: Always close file descriptors and sockets in `_cleanup()` methods

## Commands

### Development

```bash
# Install dependencies
uv sync

# Run client (local testing - requires sudo)
sudo uv run pyvpn-client --server 127.0.0.1 --port 51820 --password mysecretpassword --tun utun3

# Run server (Linux only - requires sudo)
sudo uv run pyvpn-server --port 51820 --password mysecretpassword --tun tun0
```

### AWS Deployment

```bash
# Automated deployment (interactive)
uv run python deploy.py

# Or deploy CDK stack directly (interactive)
uv run python app.py

# Manual CDK commands
cd infra
uv run cdk bootstrap              # First time only
uv run cdk synth                  # Preview CloudFormation
uv run cdk deploy PyVPNStack      # Deploy infrastructure
uv run cdk destroy PyVPNStack     # Clean up resources

# Upload server code after deployment
scp -i your-key.pem vpn_server.py ubuntu@SERVER_IP:~/pyvpn/server/
ssh -i your-key.pem ubuntu@SERVER_IP 'sudo systemctl start pyvpn'

# Monitor server logs
ssh -i your-key.pem ubuntu@SERVER_IP 'sudo journalctl -u pyvpn -f'
```

## Architecture

### Encryption Flow
1. Password → PBKDF2 (100k iterations, SHA256) → 256-bit AES key
2. Each packet: 12-byte nonce + 16-byte GCM tag + ciphertext
3. Salt is hardcoded as `pyvpn_salt_v1` (same on client/server)

### Packet Flow
**Client → Internet:**
1. Application sends packet to TUN interface (10.8.0.2)
2. Client reads from TUN, extracts IP packet (skip 4-byte macOS header)
3. Encrypt packet with AES-256-GCM
4. Send encrypted packet via UDP to server
5. Server decrypts and writes to TUN interface
6. Server forwards to internet via NAT (iptables MASQUERADE)

**Internet → Client:**
1. Internet response arrives at server's default interface
2. Routing table sends packet to TUN interface (destination 10.8.0.x)
3. Server reads from TUN, looks up client by VPN IP
4. Encrypt and send via UDP to client's address
5. Client decrypts and writes to TUN (with 4-byte protocol family header)

### TUN Interface Differences
- **macOS**: Uses `/dev/utunX`, requires 4-byte protocol family header (AF_INET = 0x00000002)
- **Linux**: Uses `/dev/net/tun` with ioctl, no header when using IFF_NO_PI flag

### CDK Infrastructure (`app.py`)
- **PyVPNStack**: Creates EC2 instance with Ubuntu 24.04, security groups, IAM role
- **User data**: Installs uv, creates project structure, configures systemd service
- **Outputs**: Instance ID, public IP, SSH command, next steps
- **Interactive prompts**: VPN password, EC2 key pair, instance type, SSH CIDR

### Deployment Helper (`deploy.py`)
Orchestrates the full deployment:
1. Check prerequisites (AWS CLI, credentials, CDK)
2. Bootstrap CDK if needed
3. Run `app.py` for interactive CDK deployment
4. Optionally upload server code via SCP and start systemd service

## File Structure

```
/
├── vpn_client.py          # VPN client (macOS)
├── vpn_server.py          # VPN server (Linux/EC2)
├── app.py                 # CDK infrastructure stack
├── deploy.py              # Deployment automation script
├── pyproject.toml         # Dependencies and entry points
├── README.md              # User-facing documentation
├── AWS_DEPLOYMENT.md      # Manual EC2 setup guide
├── CLAUDE.md              # Guidance for Claude Code (this file)
└── STYLE_GUIDE.md         # Coding standards and conventions
```

Note: The actual project structure in README.md shows a `pyvpn/` package structure, but the current files are in the root. When modifying code, maintain compatibility with both structures (imports may use `pyvpn.client.vpn_client` or just `vpn_client`).

## Important Notes

- **Root required**: Both client and server require `sudo` for TUN interface access
- **Platform-specific**: Client is macOS-only, server is Linux-only
- **Educational purposes**: Uses shared password instead of proper key exchange (WireGuard, IKEv2, etc.)
- **No replay protection**: Packets don't include sequence numbers
- **Default IPs**: Server 10.8.0.1, clients start at 10.8.0.2
- **Default port**: UDP 51820 (same as WireGuard)

## Security Considerations

This is an educational project. Production VPNs should use:
- Proper key exchange (not shared passwords)
- Perfect forward secrecy
- Replay attack protection (sequence numbers, timestamps)
- Battle-tested protocols (WireGuard, OpenVPN, IKEv2)

## AWS Costs

- t3.micro: ~$7.50/month
- t3.small: ~$15/month
- t4g.micro (ARM): ~$5/month
- Data transfer: ~$0.09/GB outbound