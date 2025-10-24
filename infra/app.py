#!/usr/bin/env python3
"""
PyVPN CDK Deployment App
Interactive AWS infrastructure deployment for your VPN server
"""

import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    CfnOutput,
    Duration,
)
import os


class PyVPNStack(Stack):
    """
    CDK Stack for PyVPN Server Infrastructure
    
    Creates:
    - VPC with public subnet
    - EC2 instance (Ubuntu 24.04)
    - Security group with VPN ports
    - IAM role for Systems Manager (optional remote access)
    - User data script to install and configure VPN
    """
    
    def __init__(
        self, 
        scope: Construct, 
        construct_id: str,
        vpn_password: str,
        instance_type: str = "t3.micro",
        allowed_ssh_cidr: str = "0.0.0.0/0",
        key_name: str = None,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # VPC - using default VPC to save costs
        # In production, you'd create a custom VPC
        vpc = ec2.Vpc.from_lookup(self, "DefaultVPC", is_default=True)
        
        # Security Group
        security_group = ec2.SecurityGroup(
            self,
            "PyVPNSecurityGroup",
            vpc=vpc,
            description="Security group for PyVPN server",
            allow_all_outbound=True,
        )
        
        # SSH access (port 22)
        security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4(allowed_ssh_cidr),
            connection=ec2.Port.tcp(22),
            description="SSH access",
        )
        
        # VPN traffic (UDP port 51820)
        security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.udp(51820),
            description="VPN UDP traffic",
        )
        
        # IAM Role for EC2 (allows SSM access - alternative to SSH)
        role = iam.Role(
            self,
            "PyVPNInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                )
            ],
        )
        
        # User Data - Script that runs on first boot
        user_data = ec2.UserData.for_linux()
        
        # Read the server installation script
        user_data.add_commands(
            "#!/bin/bash",
            "set -e",
            "",
            "# Log everything",
            "exec > >(tee /var/log/pyvpn-setup.log)",
            "exec 2>&1",
            "",
            "echo '=== PyVPN Server Installation Started ==='",
            "date",
            "",
            "# Update system",
            "apt-get update",
            "apt-get upgrade -y",
            "",
            "# Install dependencies",
            "apt-get install -y python3 python3-pip curl iptables git",
            "",
            "# Install uv as ubuntu user",
            "sudo -u ubuntu bash -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'",
            "",
            "# Clone/download PyVPN (for now, we'll create it in place)",
            "cd /home/ubuntu",
            "",
            "# Create project structure",
            "mkdir -p pyvpn/server pyvpn/client pyvpn/common",
            "chown -R ubuntu:ubuntu pyvpn",
            "",
            # Embed the server code directly
            f"cat > /home/ubuntu/pyvpn/pyproject.toml << 'PYPROJECT_EOF'",
            "[project]",
            'name = "pyvpn"',
            'version = "0.1.0"',
            'description = "Simple open-source VPN"',
            'requires-python = ">=3.10"',
            "dependencies = [",
            '    "cryptography>=46.0.3",',
            "]",
            "",
            "[project.scripts]",
            'pyvpn-server = "pyvpn.server.vpn_server:main"',
            "",
            "[build-system]",
            'requires = ["hatchling"]',
            'build-backend = "hatchling.build"',
            "",
            "[tool.hatch.build.targets.wheel]",
            'packages = ["pyvpn"]',
            "PYPROJECT_EOF",
            "",
            "# Create __init__ files",
            "touch /home/ubuntu/pyvpn/__init__.py",
            "touch /home/ubuntu/pyvpn/server/__init__.py",
            "touch /home/ubuntu/pyvpn/client/__init__.py",
            "touch /home/ubuntu/pyvpn/common/__init__.py",
            "",
            # We'll download the server script from a URL or embed it
            # For now, let's create a minimal version
            "# Note: In production, you'd git clone or download from S3",
            "echo 'Server code will be deployed separately' > /home/ubuntu/pyvpn/server/vpn_server.py",
            "",
            "# Install dependencies",
            "cd /home/ubuntu/pyvpn",
            "sudo -u ubuntu /home/ubuntu/.cargo/bin/uv sync",
            "",
            "# Create systemd service",
            f"cat > /etc/systemd/system/pyvpn.service << 'SERVICE_EOF'",
            "[Unit]",
            "Description=PyVPN Server",
            "After=network.target",
            "",
            "[Service]",
            "Type=simple",
            "User=root",
            "WorkingDirectory=/home/ubuntu/pyvpn",
            f"ExecStart=/home/ubuntu/.cargo/bin/uv run pyvpn-server --port 51820 --password {vpn_password}",
            "Restart=always",
            "RestartSec=10",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "SERVICE_EOF",
            "",
            "# Enable but don't start yet (need to upload actual code first)",
            "systemctl daemon-reload",
            "systemctl enable pyvpn",
            "",
            "echo '=== PyVPN Server Installation Complete ==='",
            "echo 'Note: Upload server code and run: sudo systemctl start pyvpn'",
            "date",
        )
        
        # Get the latest Ubuntu 24.04 AMI
        machine_image = ec2.MachineImage.from_ssm_parameter(
            "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
            os=ec2.OperatingSystemType.LINUX,
        )
        
        # EC2 Instance
        instance = ec2.Instance(
            self,
            "PyVPNInstance",
            instance_type=ec2.InstanceType(instance_type),
            machine_image=machine_image,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            security_group=security_group,
            role=role,
            user_data=user_data,
            key_name=key_name if key_name else None,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=8,  # 8 GB is plenty
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        delete_on_termination=True,
                    ),
                )
            ],
        )
        
        # Outputs
        CfnOutput(
            self,
            "InstanceId",
            value=instance.instance_id,
            description="EC2 Instance ID",
        )
        
        CfnOutput(
            self,
            "PublicIP",
            value=instance.instance_public_ip,
            description="Public IP address of VPN server",
        )
        
        CfnOutput(
            self,
            "VPNServerAddress",
            value=f"{instance.instance_public_ip}:51820",
            description="VPN server address (use this in your client)",
        )
        
        CfnOutput(
            self,
            "SSHCommand",
            value=f"ssh -i your-key.pem ubuntu@{instance.instance_public_ip}",
            description="SSH command to connect to the server",
        )
        
        CfnOutput(
            self,
            "NextSteps",
            value=(
                f"1. Wait 2-3 minutes for instance to boot\n"
                f"2. SSH to server: ssh -i your-key.pem ubuntu@{instance.instance_public_ip}\n"
                f"3. Upload server code: scp -r pyvpn/server ubuntu@{instance.instance_public_ip}:~/pyvpn/\n"
                f"4. Start VPN: sudo systemctl start pyvpn\n"
                f"5. Connect client: sudo uv run pyvpn-client --server {instance.instance_public_ip}"
            ),
            description="Next steps to complete deployment",
        )


def main():
    """
    Interactive CDK deployment with helpful prompts
    """
    import sys
    
    print("=" * 70)
    print("🚀 PyVPN AWS Deployment - Interactive Setup")
    print("=" * 70)
    print()
    
    # Get VPN password
    print("📝 Step 1: VPN Password")
    print("   This password encrypts your VPN traffic.")
    print("   Use a strong, random password (at least 16 characters)")
    print()
    vpn_password = input("   Enter VPN password: ").strip()
    
    if len(vpn_password) < 8:
        print("   ⚠️  Warning: Password is short. Recommend at least 16 characters!")
        proceed = input("   Continue anyway? (y/N): ").strip().lower()
        if proceed != 'y':
            print("   Exiting...")
            sys.exit(0)
    
    print()
    
    # Get EC2 key pair
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
    
    # Get instance type
    print("📝 Step 3: Instance Type")
    print("   Recommended options:")
    print("   - t3.micro  (1 vCPU, 1GB RAM) ~$7.50/month - Good for 1-2 users")
    print("   - t3.small  (2 vCPU, 2GB RAM) ~$15/month  - Better performance")
    print("   - t4g.micro (ARM, 1GB RAM)    ~$5/month   - Most cost-effective")
    print()
    instance_type = input("   Enter instance type [t3.micro]: ").strip() or "t3.micro"
    print()
    
    # Get SSH CIDR
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
    print(f"   VPN Password:    {'*' * len(vpn_password)}")
    print(f"   EC2 Key Pair:    {key_name or 'None (SSM access only)'}")
    print(f"   Instance Type:   {instance_type}")
    print(f"   SSH Access:      {ssh_cidr}")
    print()
    print("   Estimated Cost:  ~${:.2f}/month".format(
        7.50 if 'micro' in instance_type else 15.00
    ))
    print()
    
    proceed = input("   Deploy this configuration? (Y/n): ").strip().lower()
    if proceed == 'n':
        print("   Deployment cancelled.")
        sys.exit(0)
    
    print()
    print("🚀 Starting deployment...")
    print()
    
    # Create CDK app
    app = cdk.App()
    
    PyVPNStack(
        app,
        "PyVPNStack",
        vpn_password=vpn_password,
        instance_type=instance_type,
        allowed_ssh_cidr=ssh_cidr,
        key_name=key_name,
        env=cdk.Environment(
            account=os.getenv('CDK_DEFAULT_ACCOUNT'),
            region=os.getenv('CDK_DEFAULT_REGION', 'us-east-1'),
        ),
    )
    
    app.synth()


if __name__ == "__main__":
    main()
