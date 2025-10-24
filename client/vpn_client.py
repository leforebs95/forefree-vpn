#!/usr/bin/env python3
"""
PyVPN Client - Simple VPN client for macOS
Connects to a VPN server and routes traffic through an encrypted tunnel
"""

import socket
import struct
import select
import argparse
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from config import ConfigError, VPNConfig


class VPNClient:
    def __init__(self, server_host, server_port, password, tun_name='utun3', use_aws_secrets=False):
        """
        Initialize VPN Client
        
        Args:
            server_host: IP address or hostname of VPN server
            server_port: UDP port of VPN server
            password: Shared password for encryption
            tun_name: Name of TUN interface (utun3, utun4, etc on Mac)
        """
        self.server_host = server_host
        self.server_port = server_port
        self.tun_name = tun_name

        # Load configuration
        try:
            config = VPNConfig(use_aws_secrets=use_aws_secrets)
            # Use provided password or fall back to config
            password_to_use = password if password else config.password
            salt = config.salt
        except ConfigError as e:
            raise ConfigError(f"Failed to load VPN configuration: {e}")
        
        # Derive encryption key from password
        self.key = self._derive_key(salt, password_to_use)
        
        # Network sockets
        self.tun_fd = None
        self.udp_socket = None
        
    def _derive_key(self, salt, password):
        """Derive a 256-bit encryption key from password"""
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
        # Generate random nonce (12 bytes for GCM)
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Return: nonce + tag + ciphertext
        return nonce + encryptor.tag + ciphertext
    
    def _decrypt(self, encrypted_data):
        """Decrypt data using AES-256-GCM"""
        try:
            # Extract components
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def _create_tun_interface(self):
        """Create TUN interface on macOS"""
        try:
            # On macOS, TUN devices are at /dev/utunX
            # utun0, utun1 are often used by system, so we use utun3+
            tun_path = f'/dev/{self.tun_name}'
            
            # Open TUN device
            self.tun_fd = os.open(tun_path, os.O_RDWR)
            
            print(f"✓ Created TUN interface: {self.tun_name}")
            print(f"  File descriptor: {self.tun_fd}")
            
            return True
        except Exception as e:
            print(f"✗ Failed to create TUN interface: {e}")
            print(f"  Make sure you run this with sudo!")
            return False
    
    def _configure_tun_interface(self, client_ip='10.8.0.2', netmask='255.255.255.0'):
        """Configure the TUN interface with IP address"""
        try:
            # Set IP address
            os.system(f'ifconfig {self.tun_name} {client_ip} {client_ip} netmask {netmask} up')
            
            print(f"✓ Configured {self.tun_name} with IP: {client_ip}")
            
            # Add route to send all traffic through VPN (optional, commented for safety)
            # os.system(f'route add -net 0.0.0.0/1 -interface {self.tun_name}')
            # os.system(f'route add -net 128.0.0.0/1 -interface {self.tun_name}')
            
            return True
        except Exception as e:
            print(f"✗ Failed to configure TUN interface: {e}")
            return False
    
    def _create_udp_socket(self):
        """Create UDP socket for communication with server"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print(f"✓ Created UDP socket to {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"✗ Failed to create UDP socket: {e}")
            return False
    
    def _send_handshake(self):
        """Send initial handshake to server"""
        try:
            handshake_msg = b"PYVPN_HELLO"
            encrypted = self._encrypt(handshake_msg)
            self.udp_socket.sendto(encrypted, (self.server_host, self.server_port))
            print("✓ Sent handshake to server")
            return True
        except Exception as e:
            print(f"✗ Failed to send handshake: {e}")
            return False
    
    def start(self):
        """Start the VPN client"""
        print("=" * 60)
        print("PyVPN Client Starting...")
        print("=" * 60)
        
        # Create TUN interface
        if not self._create_tun_interface():
            return False
        
        # Configure TUN interface
        if not self._configure_tun_interface():
            return False
        
        # Create UDP socket
        if not self._create_udp_socket():
            return False
        
        # Send handshake
        if not self._send_handshake():
            return False
        
        print("\n" + "=" * 60)
        print("VPN Client Running - Press Ctrl+C to stop")
        print("=" * 60 + "\n")
        
        # Main loop
        self._run_loop()
    
    def _run_loop(self):
        """Main event loop - forward packets between TUN and UDP"""
        try:
            while True:
                # Wait for data from either TUN interface or UDP socket
                readable, _, _ = select.select([self.tun_fd, self.udp_socket], [], [], 1.0)
                
                for fd in readable:
                    if fd == self.tun_fd:
                        # Packet from TUN (going out to internet)
                        self._handle_tun_packet()
                    elif fd == self.udp_socket:
                        # Packet from server (coming back from internet)
                        self._handle_udp_packet()
        
        except KeyboardInterrupt:
            print("\n\nShutting down VPN client...")
            self._cleanup()
        except Exception as e:
            print(f"\nError in main loop: {e}")
            self._cleanup()
    
    def _handle_tun_packet(self):
        """Handle packet from TUN interface (client -> server)"""
        try:
            # Read packet from TUN
            # On macOS, first 4 bytes are protocol family
            packet = os.read(self.tun_fd, 2048)
            
            if len(packet) > 4:
                # Extract the actual IP packet (skip first 4 bytes)
                ip_packet = packet[4:]
                
                # Get destination IP for logging
                dst_ip = socket.inet_ntoa(ip_packet[16:20])
                
                print(f"→ OUT: {len(ip_packet)} bytes to {dst_ip}")
                
                # Encrypt and send to server
                encrypted = self._encrypt(ip_packet)
                self.udp_socket.sendto(encrypted, (self.server_host, self.server_port))
        
        except Exception as e:
            print(f"Error handling TUN packet: {e}")
    
    def _handle_udp_packet(self):
        """Handle packet from UDP socket (server -> client)"""
        try:
            # Receive encrypted packet from server
            encrypted_data, addr = self.udp_socket.recvfrom(2048)
            
            # Decrypt
            ip_packet = self._decrypt(encrypted_data)
            
            if ip_packet:
                # Get source IP for logging
                src_ip = socket.inet_ntoa(ip_packet[12:16])
                
                print(f"← IN:  {len(ip_packet)} bytes from {src_ip}")
                
                # Prepend protocol family for macOS (AF_INET = 2)
                protocol_family = struct.pack('!I', socket.AF_INET)
                full_packet = protocol_family + ip_packet
                
                # Write to TUN interface
                os.write(self.tun_fd, full_packet)
        
        except Exception as e:
            print(f"Error handling UDP packet: {e}")
    
    def _cleanup(self):
        """Clean up resources"""
        if self.tun_fd:
            os.close(self.tun_fd)
        if self.udp_socket:
            self.udp_socket.close()
        print("Cleanup complete")

