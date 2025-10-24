# AWS EC2 Deployment Guide

This guide walks you through deploying your PyVPN server to AWS EC2.

## Prerequisites

- AWS CLI configured (`aws configure`)
- SSH key pair for EC2 access
- Basic familiarity with AWS EC2

## Step 1: Launch EC2 Instance

### Recommended Instance Type
- **t3.micro** or **t3.small** (eligible for free tier)
- Ubuntu 24.04 LTS or Amazon Linux 2023

### Required Configuration

1. **AMI**: Ubuntu Server 24.04 LTS (or Amazon Linux 2023)
2. **Instance Type**: t3.micro (1 vCPU, 1GB RAM is sufficient)
3. **Network Settings**:
   - Enable **Auto-assign public IP**
   - Create new security group or use existing

### Security Group Rules

Create/modify security group with these inbound rules:

| Type | Protocol | Port | Source | Description |
|------|----------|------|--------|-------------|
| SSH | TCP | 22 | Your IP | SSH access |
| Custom UDP | UDP | 51820 | 0.0.0.0/0 | VPN traffic |

**Note**: For production, restrict SSH to your IP only!

## Step 2: Connect to Your Instance

```bash
ssh -i your-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

## Step 3: Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and required tools
sudo apt install -y python3 python3-pip curl iptables

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env
```

## Step 4: Deploy PyVPN

### Option A: Copy Files Manually

```bash
# On your local machine, from the pyvpn directory
scp -i your-key.pem -r pyvpn ubuntu@YOUR_EC2_PUBLIC_IP:~/
```

### Option B: Clone from Git (if you push to GitHub)

```bash
git clone https://github.com/yourusername/pyvpn.git
cd pyvpn
```

## Step 5: Install and Run Server

```bash
cd ~/pyvpn

# Sync dependencies
uv sync

# Test the server
sudo uv run pyvpn-server --port 51820 --password YOUR_SECURE_PASSWORD
```

## Step 6: Run as Background Service (Recommended)

Create a systemd service file:

```bash
sudo nano /etc/systemd/system/pyvpn.service
```

Add this content:

```ini
[Unit]
Description=PyVPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/ubuntu/pyvpn
ExecStart=/home/ubuntu/.cargo/bin/uv run pyvpn-server --port 51820 --password YOUR_SECURE_PASSWORD
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable pyvpn
sudo systemctl start pyvpn
sudo systemctl status pyvpn
```

## Step 7: Connect Your Client

On your Mac:

```bash
# In your local pyvpn directory
sudo uv run pyvpn-client --server YOUR_EC2_PUBLIC_IP --port 51820 --password YOUR_SECURE_PASSWORD
```

## Testing Your VPN

Once connected, test that traffic is routing through your VPN:

```bash
# Check your public IP (should be your EC2 IP)
curl ifconfig.me

# Test DNS
dig google.com

# Test basic connectivity
ping -c 4 8.8.8.8
```

## Monitoring and Logs

```bash
# View real-time logs
sudo journalctl -u pyvpn -f

# Check if service is running
sudo systemctl status pyvpn

# Restart service
sudo systemctl restart pyvpn
```

## Troubleshooting

### Port Not Open
```bash
# Check if port is listening
sudo netstat -tulpn | grep 51820

# Check iptables rules
sudo iptables -L -n -v
```

### Connection Refused
- Verify security group allows UDP 51820
- Check server logs: `sudo journalctl -u pyvpn -n 50`
- Verify server is running: `sudo systemctl status pyvpn`

### IP Forwarding Issues
```bash
# Verify IP forwarding is enabled
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1

# If not, enable it
sudo sysctl -w net.ipv4.ip_forward=1
```

## Cost Optimization

**Current Setup**: ~$8-10/month
- t3.micro instance: ~$7.50/month
- Data transfer: ~$0.09/GB out

**To Reduce Costs**:
1. Use **t4g.micro** (ARM-based): ~$5/month
2. Use AWS free tier (750 hours/month for 12 months)
3. Stop instance when not in use
4. Monitor data transfer with CloudWatch

## Security Hardening (Production)

1. **Change default password**:
   ```bash
   # Use a strong, random password
   sudo uv run pyvpn-server --password $(openssl rand -base64 32)
   ```

2. **Restrict SSH access**:
   - Update security group to allow SSH only from your IP
   - Use key-based auth only (disable password auth)

3. **Enable CloudWatch monitoring**:
   - Monitor CPU, network, and disk usage
   - Set up alerts for unusual activity

4. **Regular updates**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

5. **Firewall hardening**:
   ```bash
   # Only allow necessary ports
   sudo ufw allow 22/tcp
   sudo ufw allow 51820/udp
   sudo ufw enable
   ```

## Next Steps

- [ ] Test VPN connection from different networks
- [ ] Set up monitoring and alerts
- [ ] Document your specific configuration
- [ ] Consider setting up automated backups
- [ ] Explore advanced features (kill switch, split tunneling)
