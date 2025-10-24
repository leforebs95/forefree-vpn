#!/usr/bin/env python3
"""
Configuration management for PyVPN
Handles loading secrets from environment variables (local) or AWS Secrets Manager (production)
"""

import os
import base64
import json
from typing import Optional
from dotenv import load_dotenv

class ConfigError(Exception):
    """Raised when configuration is invalid or missing"""
    pass


class VPNConfig:
    """
    Manages VPN configuration from environment or AWS Secrets Manager.
    
    Priority:
    1. Environment variables (local development)
    2. AWS Secrets Manager (production)
    """
    
    def __init__(self, use_aws_secrets: bool = False):
        """
        Initialize configuration.
        
        Args:
            use_aws_secrets: If True, load from AWS Secrets Manager
                           If False, load from environment variables
        """
        self.use_aws_secrets = use_aws_secrets
        self._password: Optional[str] = None
        self._salt: Optional[bytes] = None
        
    def _load_from_env(self) -> tuple[str, bytes]:
        """Load configuration from environment variables"""
        password = os.getenv('VPN_PASSWORD')
        salt_b64 = os.getenv('VPN_SALT')
        
        if not password:
            raise ConfigError(
                "VPN_PASSWORD not found in environment.\n"
                "  Create .env file with: VPN_PASSWORD=your-password"
            )
        
        if not salt_b64:
            raise ConfigError(
                "VPN_SALT not found in environment.\n"
                "  Generate one with: python3 -c \"import os, base64; "
                "print(base64.b64encode(os.urandom(32)).decode())\"\n"
                "  Then add to .env: VPN_SALT=<generated-salt>"
            )
        
        try:
            salt = base64.b64decode(salt_b64)
        except Exception as e:
            raise ConfigError(f"Invalid VPN_SALT format (must be base64): {e}")
        
        if len(salt) != 32:
            raise ConfigError(
                f"VPN_SALT must be 32 bytes, got {len(salt)} bytes.\n"
                "  Generate a new one with: python3 -c \"import os, base64; "
                "print(base64.b64encode(os.urandom(32)).decode())\""
            )
        
        return password, salt
    
    def _load_from_aws_secrets(self) -> tuple[str, bytes]:
        """
        Load configuration from AWS Secrets Manager.
        
        Expects a secret named 'pyvpn/config' with JSON:
        {
            "password": "your-vpn-password",
            "salt": "base64-encoded-salt"
        }
        """
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            raise ConfigError(
                "boto3 not installed. Install with: uv add boto3"
            )
        
        secret_name = os.getenv('VPN_SECRET_NAME', 'pyvpn/config')
        region = os.getenv('AWS_REGION', 'us-east-1')
        
        try:
            client = boto3.client('secretsmanager', region_name=region)
            response = client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' not in response:
                raise ConfigError(f"Secret {secret_name} has no SecretString")
            
            secret_data = json.loads(response['SecretString'])
            password = secret_data.get('password')
            salt_b64 = secret_data.get('salt')
            
            if not password or not salt_b64:
                raise ConfigError(
                    f"Secret {secret_name} missing 'password' or 'salt' fields"
                )
            
            salt = base64.b64decode(salt_b64)
            
            if len(salt) != 32:
                raise ConfigError(
                    f"Salt in {secret_name} must be 32 bytes, got {len(salt)}"
                )
            
            return password, salt
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                raise ConfigError(
                    f"Secret '{secret_name}' not found in AWS Secrets Manager.\n"
                    f"  Create it with: aws secretsmanager create-secret "
                    f"--name {secret_name} --secret-string '{{\n"
                    f"    \"password\": \"your-password\",\n"
                    f"    \"salt\": \"your-base64-salt\"\n"
                    f"  }}'"
                )
            else:
                raise ConfigError(f"AWS Secrets Manager error: {e}")
    
    @property
    def password(self) -> str:
        """Get VPN password (lazy-loaded)"""
        if self._password is None:
            self._load()
        return self._password
    
    @property
    def salt(self) -> bytes:
        """Get VPN salt (lazy-loaded)"""
        if self._salt is None:
            self._load()
        return self._salt
    
    def _load(self):
        """Load configuration from appropriate source"""
        if self.use_aws_secrets:
            self._password, self._salt = self._load_from_aws_secrets()
        else:
            self._password, self._salt = self._load_from_env()


# Example usage
if __name__ == '__main__':
    # Load .env file
    load_dotenv()
    
    # Local development
    print("Testing local configuration...")
    try:
        config = VPNConfig(use_aws_secrets=False)
        print(f"✓ Password: {'*' * len(config.password)}")
        print(f"✓ Salt: {len(config.salt)} bytes")
    except ConfigError as e:
        print(f"✗ Configuration error: {e}")
    
    # AWS Secrets Manager
    print("\nTesting AWS Secrets Manager...")
    try:
        config = VPNConfig(use_aws_secrets=True)
        print(f"✓ Password: {'*' * len(config.password)}")
        print(f"✓ Salt: {len(config.salt)} bytes")
    except ConfigError as e:
        print(f"✗ Configuration error: {e}")