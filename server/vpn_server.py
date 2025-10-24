#!/usr/bin/env python3
"""
PyVPN Server - Simple VPN server for Linux (AWS EC2)
Receives encrypted packets from clients and forwards them to the internet
"""

import socket
import struct
import select
import argparse
import sys
import os
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from dotenv import load_dotenv

from config import ConfigError, VPNConfig

load_dotenv()


class VPNServer:
    def __init__(self, listen_port, password, tun_name='tun0', use_aws_secrets=False):
        """
        Initialize VPN Server
        
        Args:
            listen_port: UDP port to listen on
            password: Shared password for encryption
            tun_name: Name of TUN interface (tun0, tun1, etc on Linux)
        """
        self.listen_port = listen_port
        self.tun_name = tun_name

        # Load configuration
        try:
            config = VPNConfig(use_aws_secrets=use_aws_secrets)
            password_to_use = password if password else config.password
            salt = config.salt
        except ConfigError as e:
            raise ConfigError(f"Failed to load VPN configuration: {e}")
        
        # Derive encryption key from password
        self.key = self._derive_key(salt, password_to_use)
        
        # Network sockets
        self.tun_fd = None
        self.udp_socket = None
        
        # Connected clients: {(client_ip, client_port): last_seen_time}
        self.clients = {}
        
        # Client IP assignment
        self.next_client_ip = 2  # Start from 10.8.0.2
        self.client_ips = {}  # {(client_ip, client_port): assigned_vpn_ip}
        
    def _derive_key(self, password):
        """Derive a 256-bit encryption key from password"""
        salt = b'pyvpn_salt_v1'  # Must match client
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _encrypt(self, plaintext):
        """Encrypt data using AES-256-GCM"""
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext
    
    def _decrypt(self, encrypted_data):
        """Decrypt data using AES-256-GCM"""
        try:
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def _create_tun_interface(self):
        """Create TUN interface on Linux"""
        try:
            # On Linux, we use the universal TUN/TAP driver
            import fcntl
            
            # Constants for TUN/TAP
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000
            
            # Open the TUN device
            self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
            
            # Create the interface
            ifr = struct.pack('16sH', self.tun_name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            
            print(f"✓ Created TUN interface: {self.tun_name}")
            print(f"  File descriptor: {self.tun_fd}")
            
            return True
        except Exception as e:
            print(f"✗ Failed to create TUN interface: {e}")
            print(f"  Make sure /dev/net/tun exists and you run with sudo!")
            return False
    
    def _configure_tun_interface(self, server_ip='10.8.0.1', netmask='255.255.255.0'):
        """Configure the TUN interface with IP address and routing"""
        try:
            # Bring interface up with IP
            subprocess.run([
                'ip', 'addr', 'add', f'{server_ip}/24', 
                'dev', self.tun_name
            ], check=True)
            
            subprocess.run([
                'ip', 'link', 'set', 'dev', self.tun_name, 'up'
            ], check=True)
            
            print(f"✓ Configured {self.tun_name} with IP: {server_ip}")
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to configure TUN interface: {e}")
            return False
    
    def _enable_ip_forwarding(self):
        """Enable IP forwarding in the kernel"""
        try:
            subprocess.run([
                'sysctl', '-w', 'net.ipv4.ip_forward=1'
            ], check=True, capture_output=True)
            
            print("✓ Enabled IP forwarding")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to enable IP forwarding: {e}")
            return False
    
    def _setup_nat(self):
        """Setup NAT (Network Address Translation) using iptables"""
        try:
            # Get the default network interface
            default_iface = self._get_default_interface()
            
            if not default_iface:
                print("✗ Could not determine default network interface")
                return False
            
            print(f"  Using interface: {default_iface}")
            
            # Enable NAT (masquerading) for traffic from TUN to internet
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'POSTROUTING',
                '-o', default_iface, '-j', 'MASQUERADE'
            ], check=True)
            
            # Allow forwarding from TUN interface
            subprocess.run([
                'iptables', '-A', 'FORWARD',
                '-i', self.tun_name, '-j', 'ACCEPT'
            ], check=True)
            
            # Allow forwarding to TUN interface for established connections
            subprocess.run([
                'iptables', '-A', 'FORWARD',
                '-o', self.tun_name, '-m', 'state',
                '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'
            ], check=True)
            
            print("✓ Configured NAT and firewall rules")
            return True
        except subprocess.CalledProcessError as e:
            print(f"✗ Failed to setup NAT: {e}")
            print("  Note: This may fail if rules already exist")
            return False
    
    def _get_default_interface(self):
        """Get the default network interface"""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                check=True
            )
            # Output format: "default via X.X.X.X dev eth0 ..."
            parts = result.stdout.split()
            if 'dev' in parts:
                idx = parts.index('dev')
                return parts[idx + 1]
        except Exception as e:
            print(f"Error getting default interface: {e}")
        
        # Fallback: common names
        for iface in ['eth0', 'ens5', 'enp0s3', 'wlan0']:
            try:
                subprocess.run(['ip', 'link', 'show', iface], 
                             check=True, capture_output=True)
                return iface
            except subprocess.CalledProcessError:
                continue
        
        return None
    
    def _create_udp_socket(self):
        """Create UDP socket for listening"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.listen_port))
            print(f"✓ Listening on UDP port {self.listen_port}")
            return True
        except Exception as e:
            print(f"✗ Failed to create UDP socket: {e}")
            return False
    
    def start(self):
        """Start the VPN server"""
        print("=" * 60)
        print("PyVPN Server Starting...")
        print("=" * 60)
        
        # Create TUN interface
        if not self._create_tun_interface():
            return False
        
        # Configure TUN interface
        if not self._configure_tun_interface():
            return False
        
        # Enable IP forwarding
        if not self._enable_ip_forwarding():
            return False
        
        # Setup NAT
        if not self._setup_nat():
            print("  Warning: NAT setup failed, but continuing...")
        
        # Create UDP socket
        if not self._create_udp_socket():
            return False
        
        print("\n" + "=" * 60)
        print("VPN Server Running - Press Ctrl+C to stop")
        print("=" * 60 + "\n")
        
        # Main loop
        self._run_loop()
    
    def _run_loop(self):
        """Main event loop - forward packets between clients and internet"""
        try:
            while True:
                # Wait for data from either TUN interface or UDP socket
                readable, _, _ = select.select([self.tun_fd, self.udp_socket], [], [], 1.0)
                
                for fd in readable:
                    if fd == self.tun_fd:
                        # Packet from internet (going back to client)
                        self._handle_tun_packet()
                    elif fd == self.udp_socket:
                        # Packet from client (going out to internet)
                        self._handle_udp_packet()
        
        except KeyboardInterrupt:
            print("\n\nShutting down VPN server...")
            self._cleanup()
        except Exception as e:
            print(f"\nError in main loop: {e}")
            import traceback
            traceback.print_exc()
            self._cleanup()
    
    def _handle_tun_packet(self):
        """Handle packet from TUN interface (internet -> client)"""
        try:
            # Read packet from TUN (response from internet)
            ip_packet = os.read(self.tun_fd, 2048)
            
            if len(ip_packet) < 20:
                return
            
            # Extract destination IP (should be a client's VPN IP like 10.8.0.2)
            dst_ip = socket.inet_ntoa(ip_packet[16:20])
            src_ip = socket.inet_ntoa(ip_packet[12:16])
            
            # Find which client this packet is for
            client_addr = None
            for addr, vpn_ip in self.client_ips.items():
                if vpn_ip == dst_ip:
                    client_addr = addr
                    break
            
            if client_addr:
                print(f"← IN:  {len(ip_packet)} bytes from {src_ip} → {dst_ip} (client)")
                
                # Encrypt and send to client
                encrypted = self._encrypt(ip_packet)
                self.udp_socket.sendto(encrypted, client_addr)
            else:
                # No client found for this destination
                pass
        
        except Exception as e:
            print(f"Error handling TUN packet: {e}")
    
    def _handle_udp_packet(self):
        """Handle packet from UDP socket (client -> internet)"""
        try:
            # Receive encrypted packet from client
            encrypted_data, client_addr = self.udp_socket.recvfrom(2048)
            
            # Decrypt
            data = self._decrypt(encrypted_data)
            
            if not data:
                return
            
            # Check if this is a handshake
            if data == b"PYVPN_HELLO":
                self._handle_handshake(client_addr)
                return
            
            # Regular IP packet
            if len(data) >= 20:
                # Track this client
                self.clients[client_addr] = True
                
                # Get source and destination IPs
                src_ip = socket.inet_ntoa(data[12:16])
                dst_ip = socket.inet_ntoa(data[16:20])
                
                print(f"→ OUT: {len(data)} bytes from {src_ip} → {dst_ip}")
                
                # Write to TUN interface (forward to internet)
                os.write(self.tun_fd, data)
        
        except Exception as e:
            print(f"Error handling UDP packet: {e}")
    
    def _handle_handshake(self, client_addr):
        """Handle initial handshake from client"""
        print(f"\n✓ New client connected: {client_addr[0]}:{client_addr[1]}")
        
        # Assign VPN IP to this client
        if client_addr not in self.client_ips:
            vpn_ip = f"10.8.0.{self.next_client_ip}"
            self.client_ips[client_addr] = vpn_ip
            self.next_client_ip += 1
            print(f"  Assigned VPN IP: {vpn_ip}\n")
        
        self.clients[client_addr] = True
    
    def _cleanup(self):
        """Clean up resources and remove iptables rules"""
        print("\nCleaning up...")
        
        # Remove iptables rules
        try:
            default_iface = self._get_default_interface()
            if default_iface:
                subprocess.run([
                    'iptables', '-t', 'nat', '-D', 'POSTROUTING',
                    '-o', default_iface, '-j', 'MASQUERADE'
                ], capture_output=True)
                
                subprocess.run([
                    'iptables', '-D', 'FORWARD',
                    '-i', self.tun_name, '-j', 'ACCEPT'
                ], capture_output=True)
                
                subprocess.run([
                    'iptables', '-D', 'FORWARD',
                    '-o', self.tun_name, '-m', 'state',
                    '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'
                ], capture_output=True)
                
                print("✓ Removed iptables rules")
        except Exception as e:
            print(f"  Note: Could not remove all iptables rules: {e}")
        
        # Close file descriptors
        if self.tun_fd:
            os.close(self.tun_fd)
        if self.udp_socket:
            self.udp_socket.close()
        
        print("Cleanup complete")
