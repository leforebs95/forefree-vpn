# forefree-vpn Coding Style Guide

This document defines the coding standards, conventions, and best practices for the forefree-vpn project.

## General Principles

### Code Philosophy
1. **Clarity Over Cleverness**: Readable code beats clever code
2. **Explicit Over Implicit**: Make intentions clear
3. **Educational Value**: Code should teach concepts
4. **Practical Over Perfect**: Working code beats perfect code
5. **Comments Explain Why**: Code shows how, comments explain why

## Python Style

### Package Management
**ALWAYS use uv for Python projects. ALWAYS.**

```bash
# Initialize project
uv init

# Add dependencies
uv add package-name

# Run scripts
uv run python script.py

# Sync dependencies
uv sync
```

**Never use:**
- `pip install` directly
- `requirements.txt` (use pyproject.toml)
- `virtualenv` manually (uv handles it)

### Project Structure
```
project/
├── pyproject.toml          # Project config (NOT setup.py)
├── uv.lock                 # Locked dependencies
├── README.md               # Documentation
├── package_name/
│   ├── __init__.py
│   ├── module.py
│   └── subpackage/
└── tests/                  # Future: test suite
```

### pyproject.toml Configuration
```toml
[project]
name = "project-name"
version = "0.1.0"
description = "Clear description"
requires-python = ">=3.10"  # Not too new, not too old
dependencies = [
    "package>=1.0.0",
]

[project.scripts]
command-name = "package.module:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["package_name"]
```

### Code Organization

#### Single-File Components (Preferred for Simple Modules)
When a component is <500 lines and has a single responsibility:
```python
#!/usr/bin/env python3
"""
Module docstring explaining purpose
"""

# Imports: stdlib, third-party, local
import os
import sys
from cryptography.hazmat.primitives import hashes

# Constants at top
DEFAULT_PORT = 51820
BUFFER_SIZE = 2048

# Classes
class MainClass:
    """Clear docstring"""
    pass

# Main function
def main():
    """Entry point"""
    pass

if __name__ == '__main__':
    main()
```

#### When to Split Files
Split when:
- File exceeds 500 lines
- Multiple unrelated responsibilities
- Code is reused across components
- Testing becomes difficult

### Naming Conventions

```python
# Modules and packages
vpn_client.py          # snake_case, descriptive

# Classes
class VPNClient:       # PascalCase, noun

# Functions and methods
def encrypt_packet():  # snake_case, verb

# Constants
MAX_PACKET_SIZE = 2048 # UPPER_SNAKE_CASE

# Variables
packet_data = b''      # snake_case, descriptive

# Private (internal use)
def _internal_func():  # Leading underscore
    _temp_var = 0      # Also for temp variables
```

### Type Hints (Python 3.10+)

```python
from typing import Optional, List, Dict

def process_packet(
    data: bytes,
    length: int,
    encryption_key: bytes
) -> Optional[bytes]:
    """Process a network packet.
    
    Args:
        data: Raw packet data
        length: Packet length in bytes
        encryption_key: 32-byte encryption key
        
    Returns:
        Processed packet or None if invalid
    """
    pass

# Use type hints for:
- Function signatures
- Class attributes (when non-obvious)
- Complex return types

# Skip type hints for:
- Obvious cases (i = 0)
- Loop variables
- Very short functions
```

### Docstrings

```python
def function(arg1: str, arg2: int) -> bool:
    """
    Short one-line summary.
    
    Longer description if needed. Explain the purpose,
    not the implementation details.
    
    Args:
        arg1: Description of first argument
        arg2: Description of second argument
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When input is invalid
    """
    pass
```

### Error Handling

```python
# Good: Specific exceptions, helpful messages
try:
    result = dangerous_operation()
except FileNotFoundError as e:
    print(f"✗ Config file not found: {e}")
    print("  Create it with: touch config.json")
    sys.exit(1)
except PermissionError:
    print("✗ Permission denied. Try running with sudo.")
    sys.exit(1)

# Bad: Bare except, silent failures
try:
    result = dangerous_operation()
except:
    pass  # Don't do this!
```

### Logging and Output

```python
# User-facing output: Clear, friendly
print("=" * 60)
print("🚀 forefree-vpn Server Starting...")
print("=" * 60)
print()
print("✓ Created TUN interface: tun0")
print("✗ Failed to bind port 51820")
print("  Try: sudo lsof -i :51820")

# Debug output: Structured
print(f"→ OUT: {len(packet)} bytes to {dst_ip}")
print(f"← IN:  {len(packet)} bytes from {src_ip}")

# Symbols to use:
# ✓ Success
# ✗ Error
# → Outgoing
# ← Incoming
# ⚠️  Warning
# ℹ️  Info
# 📝 Note
# 🚀 Action
```

## Code Patterns

### Configuration via CLI Arguments

```python
import argparse

def main():
    parser = argparse.ArgumentParser(
        description='forefree-vpn Client - Simple VPN client'
    )
    parser.add_argument(
        '--server',
        default='127.0.0.1',
        help='VPN server address'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=51820,
        help='VPN server port'
    )
    parser.add_argument(
        '--password',
        default='mysecretpassword',
        help='Shared password'
    )
    
    args = parser.parse_args()
    
    # Use args
    client = VPNClient(args.server, args.port, args.password)
```

### Resource Cleanup

```python
class VPNClient:
    def __init__(self):
        self.tun_fd = None
        self.socket = None
    
    def start(self):
        try:
            self._setup()
            self._run_loop()
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            self._cleanup()
    
    def _cleanup(self):
        """Always clean up resources"""
        if self.tun_fd:
            os.close(self.tun_fd)
        if self.socket:
            self.socket.close()
```

### Event Loop Pattern

```python
import select

def _run_loop(self):
    """Main event loop using select()"""
    while True:
        # Wait for I/O on multiple file descriptors
        readable, writable, exceptional = select.select(
            [self.tun_fd, self.socket],  # Watch these
            [],                          # Don't care about writable
            [],                          # Don't care about errors
            1.0                          # Timeout after 1 second
        )
        
        for fd in readable:
            if fd == self.tun_fd:
                self._handle_tun_packet()
            elif fd == self.socket:
                self._handle_socket_packet()
```

## Infrastructure Code (CDK)

### CDK Stack Structure

```python
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    CfnOutput,
)
from constructs import Construct

class MyStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Group related resources
        # 1. Networking
        vpc = self._create_vpc()
        
        # 2. Security
        security_group = self._create_security_group(vpc)
        
        # 3. Compute
        instance = self._create_instance(vpc, security_group)
        
        # 4. Outputs
        self._create_outputs(instance)
    
    def _create_vpc(self) -> ec2.Vpc:
        """Create VPC infrastructure"""
        return ec2.Vpc(self, "VPC", ...)
```

### Interactive Deployment Scripts

```python
def main():
    print("=" * 70)
    print("🚀 Deployment - Interactive Setup")
    print("=" * 70)
    print()
    
    # Always explain what you're asking for
    print("📝 Step 1: Configuration")
    print("   This password encrypts your traffic.")
    print("   📚 Guide: https://...")
    print()
    
    # Provide defaults in brackets
    password = input("   Enter password [default]: ").strip() or "default"
    
    # Validate input
    if len(password) < 8:
        print("   ⚠️  Warning: Password too short!")
        proceed = input("   Continue? (y/N): ").lower()
        if proceed != 'y':
            sys.exit(0)
    
    # Show summary before action
    print("\n" + "=" * 70)
    print("📋 Summary")
    print("=" * 70)
    print(f"   Password: {'*' * len(password)}")
    print()
    
    proceed = input("   Deploy? (Y/n): ").lower()
    if proceed == 'n':
        print("   Cancelled.")
        sys.exit(0)
```

## Documentation Standards

### README Structure
```markdown
# Project Name

One-line description.

## Features
- Bullet list of capabilities

## Setup
Step-by-step installation

## Usage
Example commands with output

## Architecture
High-level diagram

## Contributing
How to help

## License
License info
```

### Code Comments

```python
# Good comments explain WHY
def _encrypt(self, data: bytes) -> bytes:
    # Use GCM mode for authenticated encryption
    # This prevents tampering attacks
    nonce = os.urandom(12)
    ...

# Bad comments explain WHAT (code already shows this)
def _encrypt(self, data: bytes) -> bytes:
    # Generate a random nonce
    nonce = os.urandom(12)
    # Create cipher
    cipher = Cipher(...)
```

### Inline Documentation

```python
# Use docstrings for public APIs
def public_function():
    """Users call this."""
    pass

# Use comments for complex logic
def _internal_function():
    # Complex algorithm explanation
    # Reference: https://...
    pass
```

## File Organization

### Directory Structure
```
forefree-vpn/
├── client/              # Client code
│   ├── __init__.py
│   └── vpn_client.py
├── server/              # Server code
│   ├── __init__.py
│   └── vpn_server.py
├── common/              # Shared utilities (when needed)
│   ├── __init__.py
│   └── crypto.py
├── infra/               # Infrastructure code
│   ├── app.py
│   ├── deploy.py
│   └── cdk.json
├── docs/                # Documentation
│   ├── ARCHITECTURE.md
│   └── STYLE_GUIDE.md
├── pyproject.toml       # Project config
├── uv.lock             # Locked deps
└── README.md           # Main docs
```

## Testing Approach

### Manual Testing (Current)
```bash
# Test locally first
python vpn_client.py --server 127.0.0.1

# Then test on network
python vpn_client.py --server 192.168.1.100

# Finally test on AWS
python vpn_client.py --server ec2-public-ip
```

### Future: Automated Tests
```python
import pytest

def test_encryption():
    """Encrypt and decrypt should roundtrip"""
    client = VPNClient(...)
    plaintext = b"test data"
    encrypted = client._encrypt(plaintext)
    decrypted = client._decrypt(encrypted)
    assert decrypted == plaintext
```

## Git Practices

### Commit Messages
```
feat: Add CDK deployment automation
fix: Handle UDP socket timeout correctly
docs: Update deployment guide with costs
refactor: Extract encryption to common module
test: Add encryption roundtrip test
```

### Branch Strategy
- `main`: Stable, working code
- `dev`: Development branch
- `feature/x`: Feature branches

## Key Rules

### The Big Ones
1. ✅ **ALWAYS use uv** for Python projects
2. ✅ **Test locally** before deploying to AWS
3. ✅ **Document as you go** - don't wait
4. ✅ **Keep it simple** - resist overengineering
5. ✅ **Clean up resources** - close FDs, sockets

### Code Review Checklist
- [ ] Uses uv (not pip)
- [ ] Has type hints on functions
- [ ] Has docstrings on public APIs
- [ ] Includes error handling
- [ ] Cleans up resources
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No sensitive data hardcoded

## Tools and Linting

### Recommended (Future)
```bash
# Type checking
uv run mypy forefree-vpn/

# Linting
uv run ruff check forefree-vpn/

# Formatting
uv run black forefree-vpn/
```

Currently: Manual review for readability and correctness.

## References

- **PEP 8**: Python style guide
- **PEP 257**: Docstring conventions
- **uv docs**: https://github.com/astral-sh/uv
- **AWS CDK Python**: https://docs.aws.amazon.com/cdk/api/v2/python/
