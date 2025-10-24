import argparse
import os
import sys
from dotenv import load_dotenv
from common.config import ConfigError
from client.vpn_client import VPNClient

def main():
    parser = argparse.ArgumentParser(description='PyVPN Client - Simple VPN client')
    parser.add_argument('--server', default='127.0.0.1', help='VPN server address')
    parser.add_argument('--port', type=int, default=51820, help='VPN server port')
    parser.add_argument('--password', default='mysecretpassword', help='Shared password')
    parser.add_argument('--tun', default='utun3', help='TUN interface name')
    parser.add_argument('--use-aws-secrets', action='store_true', help='Use AWS Secrets Manager')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Load .env file (for local development)
    load_dotenv()
    
    # Create client
    try:
        client = VPNClient(
            server_host=args.server,
            server_port=args.port,
            password=args.password,  # Can be None
            tun_name=args.tun,
            use_aws_secrets=args.use_aws_secrets
        )
        
        client.start()
    except ConfigError as e:
        print(f"✗ Configuration error: {e}")
        print()
        print("💡 Quick fix:")
        print("   1. Copy .env.example to .env")
        print("   2. Generate salt: python3 -c \"import os, base64; print(base64.b64encode(os.urandom(32)).decode())\"")
        print("   3. Add VPN_PASSWORD and VPN_SALT to .env")
        sys.exit(1)


if __name__ == '__main__':
    main()
