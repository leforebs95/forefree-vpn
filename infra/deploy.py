#!/usr/bin/env python3
"""
PyVPN Deployment Helper
Simplifies the entire deployment process with step-by-step guidance
"""

import subprocess
import sys
import os
import time
import json

from dotenv import load_dotenv
load_dotenv()


def run_command(cmd, description, check=True, capture_output=False, stdin=None):
    """Run a shell command with nice output"""
    print(f"   → {description}...")
    try:
        if capture_output:
            result = subprocess.run(
                cmd, 
                shell=True, 
                check=check, 
                capture_output=True, 
                text=True
            )
            return result.stdout.strip()
        else:
            subprocess.run(cmd, shell=True, check=check, stdin=stdin)
            return None
    except subprocess.CalledProcessError as e:
        print(f"   ✗ Error: {e}")
        if capture_output and e.stderr:
            print(f"   {e.stderr}")
        return None


def check_prerequisites():
    """Check if required tools are installed"""
    print("🔍 Checking prerequisites...")
    print()
    
    # Check AWS CLI
    aws_version = run_command(
        "aws --version", 
        "Checking AWS CLI",
        check=False,
        capture_output=True
    )
    
    if not aws_version:
        print("   ✗ AWS CLI not found!")
        print("   📚 Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html")
        return False
    else:
        print(f"   ✓ AWS CLI found: {aws_version.split()[0]}")
    
    # Check AWS credentials
    credentials_check = run_command(
        "aws sts get-caller-identity",
        "Checking AWS credentials",
        check=False,
        capture_output=True
    )
    
    if not credentials_check:
        print("   ✗ AWS credentials not configured!")
        print("   📚 Configure: aws configure")
        print("   📚 Guide: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html")
        return False
    else:
        identity = json.loads(credentials_check)
        print(f"   ✓ AWS credentials configured")
        print(f"     Account: {identity.get('Account')}")
        print(f"     User: {identity.get('Arn', '').split('/')[-1]}")
    
    # Check CDK
    cdk_version = run_command(
        "cdk --version",
        "Checking AWS CDK",
        check=False,
        capture_output=True
    )
    
    if not cdk_version:
        print("   ℹ️  AWS CDK CLI not found (optional)")
        print("   📚 Install: npm install -g aws-cdk")
        print("   📚 Or we can use: uv run cdk")
        use_uv_cdk = input("\n   Use 'uv run cdk' instead? (Y/n): ").strip().lower()
        if use_uv_cdk == 'n':
            return False
        return "uv"
    else:
        print(f"   ✓ AWS CDK found: {cdk_version}")
        return "cdk"
    
    return True


def bootstrap_cdk(cdk_cmd):
    """Bootstrap CDK in the AWS account"""
    print("\n📦 CDK Bootstrap")
    print("   CDK needs to create some resources in your AWS account.")
    print("   This only needs to be done once per account/region.")
    print()
    
    already_bootstrapped = input("   Have you already bootstrapped CDK? (y/N): ").strip().lower()
    
    if already_bootstrapped != 'y':
        print("\n   Bootstrapping CDK...")
        region = os.getenv('AWS_REGION', 'us-east-1')
        print(f"   Region: {region}")
        
        if cdk_cmd == "uv":
            run_command(f"uv run cdk bootstrap", "Bootstrapping CDK", stdin=sys.stdin)
        else:
            run_command("cdk bootstrap", "Bootstrapping CDK", stdin=sys.stdin)
        
        print("   ✓ CDK bootstrapped!")
    else:
        print("   ✓ Skipping bootstrap")


def deploy_stack(cdk_cmd):
    """Deploy the VPN stack"""
    print("\n🚀 Deploying VPN Stack")
    print("   This will create your EC2 instance and all infrastructure.")
    print()
    
    if cdk_cmd == "uv":
        cmd = "uv run python app.py"
    else:
        cmd = "python3 app.py"
    
    # The app.py will handle interactive prompts
    result = subprocess.run(cmd, shell=True, stdin=sys.stdin)
    
    if result.returncode != 0:
        print("\n   ✗ Deployment failed!")
        return False
    
    return True


def upload_server_code(server_ip, key_file):
    """Upload the server code to EC2"""
    print("\n📤 Uploading Server Code")
    print()
    
    if not key_file:
        print("   ⚠️  No SSH key provided - you'll need to upload code manually")
        print("   📚 Guide: Use AWS Systems Manager Session Manager")
        return
    
    print(f"   Waiting for instance to be ready...")
    print("   (This can take 2-3 minutes after deployment)")
    print()
    
    # Wait a bit for instance to boot
    for i in range(30, 0, -10):
        print(f"   Waiting {i} seconds...", end='\r')
        time.sleep(10)
    
    print("\n")
    
    # Test SSH connection
    print("   Testing SSH connection...")
    ssh_test = run_command(
        f"ssh -i {key_file} -o ConnectTimeout=10 -o StrictHostKeyChecking=no ubuntu@{server_ip} 'echo connected'",
        "Testing SSH",
        check=False,
        capture_output=True
    )
    
    if not ssh_test or 'connected' not in ssh_test:
        print("   ⚠️  SSH not ready yet. Please wait a bit longer and run:")
        print(f"   $ scp -i {key_file} -r pyvpn/server ubuntu@{server_ip}:~/pyvpn/")
        return
    
    # Upload server code
    print("   ✓ SSH connection successful!")
    print("   Uploading server code...")
    
    run_command(
        f"scp -i {key_file} -o StrictHostKeyChecking=no -r pyvpn/server/vpn_server.py ubuntu@{server_ip}:~/pyvpn/server/",
        "Uploading vpn_server.py"
    )
    
    # Start the service
    print("   Starting VPN service...")
    run_command(
        f"ssh -i {key_file} -o StrictHostKeyChecking=no ubuntu@{server_ip} 'sudo systemctl start pyvpn'",
        "Starting VPN service"
    )
    
    # Check status
    time.sleep(2)
    status = run_command(
        f"ssh -i {key_file} -o StrictHostKeyChecking=no ubuntu@{server_ip} 'sudo systemctl is-active pyvpn'",
        "Checking service status",
        check=False,
        capture_output=True
    )
    
    if status and 'active' in status:
        print("   ✓ VPN service is running!")
    else:
        print("   ⚠️  VPN service may not be running. Check logs:")
        print(f"   $ ssh -i {key_file} ubuntu@{server_ip} 'sudo journalctl -u pyvpn -n 50'")


def main():
    """Main deployment flow"""
    print()
    print("=" * 70)
    print("🚀 PyVPN - Automated AWS Deployment")
    print("=" * 70)
    print()
    print("This script will guide you through deploying your VPN to AWS.")
    print("It will:")
    print("  1. Check prerequisites (AWS CLI, credentials, CDK)")
    print("  2. Bootstrap CDK (if needed)")
    print("  3. Deploy infrastructure (EC2, security groups, etc.)")
    print("  4. Upload and start the VPN server")
    print()
    
    proceed = input("Ready to begin? (Y/n): ").strip().lower()
    if proceed == 'n':
        print("Deployment cancelled.")
        sys.exit(0)
    
    print()
    
    # Check prerequisites
    cdk_cmd = check_prerequisites()
    if not cdk_cmd:
        print("\n❌ Prerequisites check failed. Please fix the issues above.")
        sys.exit(1)
    
    print("\n✓ All prerequisites met!")
    
    # Bootstrap CDK
    bootstrap_cdk(cdk_cmd)
    
    # Deploy stack
    if not deploy_stack(cdk_cmd):
        print("\n❌ Deployment failed!")
        sys.exit(1)
    
    print("\n✅ Deployment complete!")
    print()
    print("=" * 70)
    print("🎉 Your VPN is (almost) ready!")
    print("=" * 70)
    print()
    print("Next steps:")
    print("  1. Note your server's public IP from the output above")
    print("  2. Wait 2-3 minutes for the instance to fully boot")
    print("  3. Upload server code (or use the automated upload)")
    print("  4. Connect your client!")
    print()
    print("Connect command:")
    print("  $ sudo uv run pyvpn-client --server YOUR_SERVER_IP --password YOUR_PASSWORD")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDeployment interrupted.")
        sys.exit(1)
