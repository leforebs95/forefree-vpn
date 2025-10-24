import argparse
import os
import sys

from dotenv import load_dotenv
from common.config import ConfigError
from server.vpn_server import VPNServer

def main():
    parser = argparse.ArgumentParser(description='PyVPN Server - Simple VPN server')
    parser.add_argument('--port', type=int, default=51820, help='UDP port to listen on')
    parser.add_argument('--password', default='mysecretpassword', help='Shared password')
    parser.add_argument('--tun', default='tun0', help='TUN interface name')
    parser.add_argument('--use-aws-secrets', action='store_true', help='Use AWS Secrets Manager')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Load .env file (for local development)
    load_dotenv()
    
    # Create server
    try:
        server = VPNServer(
            listen_port=args.port,
            password=args.password,  # Can be None
            tun_name=args.tun,
            use_aws_secrets=args.use_aws_secrets
        )
        
        server.start()
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