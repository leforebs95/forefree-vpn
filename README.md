# PyVPN - Simple Open Source VPN

A simple, educational VPN implementation in Python for learning networking fundamentals.

## Project Structure

```
pyvpn/
├── client/
│   ├── __init__.py
│   └── vpn_client.py    # VPN client (Mac)
├── server/
│   ├── __init__.py
│   └── vpn_server.py    # VPN server (Linux/AWS)
├── infra/
│   ├── app.py           # CDK infrastructure definition
│   ├── deploy.py        # Automated deployment script
│   ├── cdk.json         # CDK configuration
│   └── README.md        # Deployment guide
├── common/
│   └── __init__.py      # Shared utilities
├── pyproject.toml       # Project configuration (uv)
├── uv.lock             # Locked dependencies
├── README.md           # This file
└── AWS_DEPLOYMENT.md   # Manual EC2 setup guide
```

## Setup

1. **Install uv** (if you don't have it):
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Sync dependencies:**
   ```bash
   uv sync
   ```

3. **On macOS**, TUN devices are available by default at `/dev/utunX`

## Deployment

### Quick Deploy to AWS (Automated)

Use our interactive CDK deployment:

```bash
uv run python infra/deploy.py
```

This script will:
- ✅ Check prerequisites (AWS CLI, credentials)
- ✅ Guide you through configuration
- ✅ Deploy infrastructure automatically
- ✅ Upload and start the VPN server

**See [infra/README.md](infra/README.md) for detailed deployment guide.**

### Manual AWS Deployment

See **[AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md)** for manual EC2 setup.

## Usage

### Running the Server (AWS EC2)

See **[AWS_DEPLOYMENT.md](AWS_DEPLOYMENT.md)** for complete deployment guide.

Quick start on Linux:
```bash
sudo uv run pyvpn-server --port 51820 --password YOUR_SECURE_PASSWORD
```

### Running the Client (Local Testing)

```bash
# Must run with sudo for TUN interface access
sudo uv run pyvpn-client --server 127.0.0.1 --port 51820 --password mysecretpassword

# Or if you prefer the module syntax:
sudo uv run python -m pyvpn.client.vpn_client --server 127.0.0.1 --port 51820
```

### Options

- `--server`: VPN server address (default: 127.0.0.1)
- `--port`: VPN server port (default: 51820)
- `--password`: Shared password for encryption (default: mysecretpassword)
- `--tun`: TUN interface name (default: utun3)

## How It Works

1. **TUN Interface**: Creates a virtual network interface that captures IP packets
2. **Encryption**: Uses AES-256-GCM to encrypt all traffic
3. **UDP Transport**: Sends encrypted packets to the VPN server
4. **Routing**: Server forwards packets to the internet and returns responses

## Next Steps

- [x] Build the VPN client
- [x] Build the VPN server
- [ ] Test locally with client and server
- [ ] Deploy server to AWS EC2
- [ ] Test from different networks
- [ ] Add authentication improvements
- [ ] Add connection health monitoring

## Security Notes

⚠️ This is an educational project! For production use:
- Use proper key exchange (not shared passwords)
- Implement perfect forward secrecy
- Add replay attack protection
- Use a battle-tested VPN protocol like WireGuard

## Learning Goals

This project teaches:
- Low-level networking (TUN interfaces, raw packets)
- Symmetric encryption (AES-GCM)
- UDP socket programming
- Packet routing and NAT
- Client-server architecture
