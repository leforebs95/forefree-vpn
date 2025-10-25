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


def setup_cdk_environment():
    """Set up CDK environment variables if not already set"""
    print()
    if not os.getenv('CDK_DEFAULT_ACCOUNT'):
        account_id = run_command(
            "aws sts get-caller-identity --query Account --output text",
            "Getting AWS account ID",
            check=True,
            capture_output=True
        )
        if account_id:
            os.environ['CDK_DEFAULT_ACCOUNT'] = account_id
            print(f"   ✓ Set CDK_DEFAULT_ACCOUNT: {account_id}")
        else:
            print("   ✗ Could not determine AWS account ID")
            return False
    else:
        print(f"   ✓ Using CDK_DEFAULT_ACCOUNT: {os.getenv('CDK_DEFAULT_ACCOUNT')}")
    
    if not os.getenv('CDK_DEFAULT_REGION'):
        region = run_command(
            "aws configure get region",
            "Getting AWS region",
            check=False,
            capture_output=True
        )
        if not region:
            region = "us-west-1"
            print(f"   ℹ️  No default region configured, using: {region}")
        
        os.environ['CDK_DEFAULT_REGION'] = region
        print(f"   ✓ Set CDK_DEFAULT_REGION: {region}")
    else:
        print(f"   ✓ Using CDK_DEFAULT_REGION: {os.getenv('CDK_DEFAULT_REGION')}")
    
    return True


def run_command(cmd, description, check=True, capture_output=False):
    """Run a shell command with nice output

    Returns:
        - If capture_output=True: stdout string on success, None on failure
        - If capture_output=False: True on success, False on failure
    """
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
            result = subprocess.run(cmd, shell=True, check=check)
            return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"   ✗ Error: {e}")
        if capture_output and e.stderr:
            print(f"   {e.stderr}")
        return None if capture_output else False


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
    """Bootstrap CDK in the AWS account

    Returns:
        True if bootstrap succeeded or was skipped, False otherwise
    """
    print("\n📦 CDK Bootstrap")
    print("   CDK needs to create some resources in your AWS account.")
    print("   This only needs to be done once per account/region.")
    print()

    already_bootstrapped = input("   Have you already bootstrapped CDK? (y/N): ").strip().lower()

    if already_bootstrapped != 'y':
        print("\n   Bootstrapping CDK...")
        region = os.getenv('CDK_DEFAULT_REGION', 'us-west-1')
        print(f"   Region: {region}")

        success = False
        if cdk_cmd == "uv":
            success = run_command(f"uv run cdk bootstrap", "Bootstrapping CDK")
        else:
            success = run_command("cdk bootstrap", "Bootstrapping CDK")

        if not success:
            print("   ✗ CDK bootstrap failed!")
            return False

        print("   ✓ CDK bootstrapped!")
    else:
        print("   ✓ Skipping bootstrap")

    return True


def collect_deployment_config():
    """Collect deployment configuration from user"""
    print("\n📝 Deployment Configuration")
    print("=" * 70)
    print()

    # Check if .env exists
    if not os.path.exists('../.env'):
        print("⚠️  No .env file found!")
        print()
        print("First, run the configuration setup:")
        print("   $ uv run setup-config")
        print()
        proceed = input("   Continue without .env? (y/N): ").strip().lower()
        if proceed != 'y':
            print("   Run 'uv run setup-config' first, then try again.")
            sys.exit(0)
        print()

    # Step 1: VPN Secret
    print("📝 Step 1: VPN Secret Configuration")
    print("   You can use an existing AWS secret or create a new one.")
    print()

    use_existing = input("   Use existing AWS secret? (Y/n): ").strip().lower()

    if use_existing != 'n':
        secret_name = os.getenv('VPN_SECRET_NAME', 'pyvpn/config')

        # Try to verify it exists
        try:
            import boto3
            client = boto3.client('secretsmanager')
            client.describe_secret(SecretId=secret_name)
            print(f"   ✓ Found secret: {secret_name}")
        except Exception as e:
            print(f"   ⚠️  Could not verify secret: {e}")
            print()
            print("   Create it first with: uv run setup-config")
            proceed = input("   Continue anyway? (y/N): ").strip().lower()
            if proceed != 'y':
                sys.exit(0)
    else:
        secret_name = None
        print("   ⚠️  Server will need password in .env file")

    print()

    # Step 2: EC2 key pair
    print("📝 Step 2: EC2 Key Pair (for SSH access)")
    print("   You need an EC2 key pair to SSH into your server.")
    print("   📚 How to create: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html")
    print()
    print("   List your existing key pairs:")
    print("   $ aws ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output table")
    print()
    key_name = input("   Enter key pair name (or press Enter to skip SSH access): ").strip()

    if not key_name:
        print("   ⚠️  Skipping SSH key - you'll use AWS Systems Manager instead")
        key_name = None

    print()

    # Step 3: Instance type
    print("📝 Step 3: Instance Type")
    print("   Recommended options:")
    print("   - t3.micro  (1 vCPU, 1GB RAM) ~$7.50/month - Good for 1-2 users")
    print("   - t3.small  (2 vCPU, 2GB RAM) ~$15/month  - Better performance")
    print("   - t4g.micro (ARM, 1GB RAM)    ~$5/month   - Most cost-effective")
    print()
    instance_type = input("   Enter instance type [t3.micro]: ").strip() or "t3.micro"
    print()

    # Step 4: SSH CIDR
    print("📝 Step 4: SSH Access (Security)")
    print("   Restrict SSH access to your IP for better security.")
    print("   Find your IP: curl ifconfig.me")
    print()
    print("   Options:")
    print("   - Your IP only: YOUR.IP.ADDRESS/32 (most secure)")
    print("   - Anywhere: 0.0.0.0/0 (less secure, but convenient)")
    print()
    ssh_cidr = input("   Enter allowed SSH CIDR [0.0.0.0/0]: ").strip() or "0.0.0.0/0"
    print()

    # Summary
    print("=" * 70)
    print("📋 Deployment Summary")
    print("=" * 70)
    print(f"   Secret Name:     {secret_name or 'None (use .env password)'}")
    print(f"   EC2 Key Pair:    {key_name or 'None (SSM access only)'}")
    print(f"   Instance Type:   {instance_type}")
    print(f"   SSH Access:      {ssh_cidr}")
    print(f"   Region:          {os.getenv('CDK_DEFAULT_REGION', 'us-west-1')}")
    print()
    print("   Estimated Cost:  ~${:.2f}/month".format(
        7.50 if 'micro' in instance_type else 15.00
    ))
    print()

    proceed = input("   Deploy this configuration? (Y/n): ").strip().lower()
    if proceed == 'n':
        print("   Deployment cancelled.")
        sys.exit(0)

    return {
        'secret_name': secret_name,
        'key_name': key_name,
        'instance_type': instance_type,
        'ssh_cidr': ssh_cidr,
        'account': os.getenv('CDK_DEFAULT_ACCOUNT'),
        'region': os.getenv('CDK_DEFAULT_REGION', 'us-west-1'),
    }


def deploy_stack(config):
    """Deploy the VPN stack using collected configuration"""
    print()
    print("🚀 Starting deployment...")
    print()

    # Import and call the deploy function from app.py
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from app import deploy

    try:
        deploy(
            secret_name=config['secret_name'],
            key_name=config['key_name'],
            instance_type=config['instance_type'],
            ssh_cidr=config['ssh_cidr'],
            account=config['account'],
            region=config['region'],
        )
        return True
    except Exception as e:
        print(f"\n   ✗ Deployment failed: {e}")
        import traceback
        traceback.print_exc()
        return False


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
    
    # Set up CDK environment
    print("\n🔧 Setting up CDK environment...")
    if not setup_cdk_environment():
        print("\n❌ Could not set up CDK environment!")
        sys.exit(1)
    
    # Bootstrap CDK
    if not bootstrap_cdk(cdk_cmd):
        print("\n❌ CDK bootstrap failed!")
        sys.exit(1)

    # Collect deployment configuration
    config = collect_deployment_config()

    # Deploy stack
    if not deploy_stack(config):
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
