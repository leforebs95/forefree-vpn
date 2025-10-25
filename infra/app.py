#!/usr/bin/env python3
"""
PyVPN CDK Deployment App
Interactive AWS infrastructure deployment for your VPN server
"""
from dotenv import load_dotenv
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager,
    CfnOutput,
    Duration,
)
import os

load_dotenv()

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
        secret_name: str,
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

        # Reference existing secret (don't create it)
        if secret_name:
            vpn_secret = secretsmanager.Secret.from_secret_name_v2(
                self,
                "VPNSecret",
                secret_name=secret_name
            )
            
            # Grant read access to EC2 instance
            vpn_secret.grant_read(role)
            
            use_aws_secrets_flag = "--use-aws-secrets"
            
            # Output
            CfnOutput(
                self,
                "SecretName",
                value=secret_name,
                description="AWS Secrets Manager secret name",
            )
        else:
            use_aws_secrets_flag = ""
        
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
            "# Load TUN kernel module (critical for VPN functionality)",
            "echo '>>> Loading TUN kernel module...'",
            "modprobe tun",
            "echo 'tun' >> /etc/modules",  # Persist across reboots
            "",
            "# Verify TUN device exists",
            "if [ -e /dev/net/tun ]; then",
            "    echo '✓ TUN device available at /dev/net/tun'",
            "else",
            "    echo '✗ WARNING: TUN device not found!'",
            "    exit 1",
            "fi",
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
            f"ExecStart=/home/ubuntu/.cargo/bin/uv run pyvpn-server --port 51820 {use_aws_secrets_flag}",
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


def deploy(
    secret_name: str = None,
    key_name: str = None,
    instance_type: str = "t3.micro",
    ssh_cidr: str = "0.0.0.0/0",
    account: str = None,
    region: str = "us-west-1"
):
    """
    Deploy the PyVPN CDK stack

    Args:
        secret_name: AWS Secrets Manager secret name for VPN password
        key_name: EC2 key pair name for SSH access
        instance_type: EC2 instance type (default: t3.micro)
        ssh_cidr: CIDR block for SSH access (default: 0.0.0.0/0)
        account: AWS account ID (auto-detected if not provided)
        region: AWS region (default: us-west-1)
    """
    app = cdk.App()

    PyVPNStack(
        app,
        "PyVPNStack",
        secret_name=secret_name,
        instance_type=instance_type,
        allowed_ssh_cidr=ssh_cidr,
        key_name=key_name,
        env=cdk.Environment(
            account=account or os.getenv('CDK_DEFAULT_ACCOUNT'),
            region=region or os.getenv('CDK_DEFAULT_REGION', 'us-west-1'),
        ),
    )

    app.synth()


if __name__ == "__main__":
    # When run directly, just deploy with environment defaults
    deploy()
