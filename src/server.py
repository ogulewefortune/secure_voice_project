"""
Server module for secure voice communication.
Handles server-side connection, audio distribution, and decryption.
"""

import socket
import threading
import time
from datetime import datetime
from src.config import DEFAULT_HOST, DEFAULT_PORT
from src.network_protocol import establish_connection, send_message, receive_message, close_connection
from src.crypto_utils import generate_key_pair, serialize_public_key, deserialize_public_key, derive_shared_secret, derive_aes_key, decrypt_data, encrypt_data
from src.audio_compression import verify_integrity, add_integrity_check
from src.intrusion_detection import get_ids, ThreatType


class VoiceServer:
    """Server for secure voice communication."""
    
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.client_keys = {}
        self.client_names = {}  # Map socket -> client name
        self.client_socket_map = {}  # Map client name -> socket (for reverse lookup)
        self.running = False
        self.ids = get_ids()
        
        # Register alert callback
        self.ids.register_alert_callback(self._on_security_alert)
    
    def log(self, message, level="INFO"):
        """Log a message with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def _on_security_alert(self, alert):
        """Handle security alert."""
        self.log(f"SECURITY ALERT: {alert}", "ALERT")
        # Note: The web server's callback should also be called since they share the same IDS instance
        # If running in separate processes, alerts won't propagate automatically
    
    def start(self):
        """Start the server."""
        self.server_socket = establish_connection(self.host, self.port, is_server=True)
        if not self.server_socket:
            self.log("Failed to start server", "ERROR")
            return
        
        self.running = True
        self.log("=" * 60)
        self.log("Secure Voice Communication Server")
        self.log("=" * 60)
        self.log(f"Server started on {self.host}:{self.port}")
        self.log("Waiting for clients...")
        self.log("=" * 60)
        
        # Generate server key pair
        self.private_key, self.public_key = generate_key_pair()
        self.log("Server key pair generated (ECDH)")
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.log(f"New client connecting from {address[0]}:{address[1]}", "CONNECT")
                
                # Detect suspicious connection patterns
                self.ids.detect_suspicious_connection_pattern(address[0])
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    self.log(f"Error accepting connection: {e}", "ERROR")
    
    def handle_client(self, client_socket, address):
        """Handle a client connection."""
        client_id = f"{address[0]}:{address[1]}"
        try:
            self.log(f"[{client_id}] Starting key exchange...", "KEY_EXCHANGE")
            
            # Send server public key
            server_pub_key_bytes = serialize_public_key(self.public_key)
            send_message(client_socket, 'K', server_pub_key_bytes)
            self.log(f"[{client_id}] Sent server public key", "KEY_EXCHANGE")
            
            # Receive client public key
            msg_type, client_pub_key_bytes = receive_message(client_socket)
            if msg_type != 'K' or not client_pub_key_bytes:
                self.log(f"[{client_id}] Failed to receive client public key", "ERROR")
                # Detect suspicious key exchange failure
                self.ids.detect_key_exchange_failure(address[0], "Invalid or missing public key")
                close_connection(client_socket)
                return
            
            client_public_key = deserialize_public_key(client_pub_key_bytes)
            self.log(f"[{client_id}] Received client public key", "KEY_EXCHANGE")
            
            # Derive shared secret and AES key
            try:
                shared_secret = derive_shared_secret(self.private_key, client_public_key)
                aes_key, salt = derive_aes_key(shared_secret)
                self.client_keys[client_socket] = aes_key
                
                # Send salt to client
                send_message(client_socket, 'S', salt)
                self.log(f"[{client_id}] Secure connection established (AES-256-GCM)", "SECURE")
                self.log(f"[{client_id}] Active clients: {len(self.clients) + 1}", "STATUS")
                
                # Reset counters on successful key exchange
                self.ids.reset_ip_counters(address[0])
                
                # Add client to list
                self.clients.append(client_socket)
                
                # Request client name
                send_message(client_socket, 'N', b'')  # Request name
                msg_type, name_data = receive_message(client_socket)
                if msg_type == 'N' and name_data:
                    client_name = name_data.decode('utf-8', errors='ignore')
                    # Handle duplicate names by appending a number
                    original_name = client_name
                    counter = 1
                    while client_name in self.client_socket_map:
                        client_name = f"{original_name}_{counter}"
                        counter += 1
                    self.client_names[client_socket] = client_name
                    self.client_socket_map[client_name] = client_socket
                    self.log(f"[{client_id}] Client registered as: {client_name}", "INFO")
                else:
                    # Use default name
                    default_name = f"Client_{len(self.clients)}"
                    # Handle duplicate names
                    original_name = default_name
                    counter = 1
                    while default_name in self.client_socket_map:
                        default_name = f"{original_name}_{counter}"
                        counter += 1
                    self.client_names[client_socket] = default_name
                    self.client_socket_map[default_name] = client_socket
            except Exception as e:
                self.log(f"[{client_id}] Key derivation failed: {e}", "ERROR")
                self.ids.detect_key_exchange_failure(address[0], f"Key derivation error: {str(e)}")
                close_connection(client_socket)
                return
            
            # Handle audio data
            audio_packet_count = 0
            while self.running:
                msg_type, encrypted_data = receive_message(client_socket)
                if not msg_type or not encrypted_data:
                    break
                
                if msg_type == 'A':  # Broadcast audio data
                    try:
                        audio_packet_count += 1
                        packet_size = len(encrypted_data)
                        
                        # Decrypt audio
                        aes_key = self.client_keys.get(client_socket)
                        if aes_key:
                            try:
                                audio_with_integrity = decrypt_data(encrypted_data, aes_key)
                                audio_size = len(audio_with_integrity)
                                
                                # Verify integrity with sender's key
                                sender_integrity_key = aes_key[:16]
                                is_valid, audio_data = verify_integrity(audio_with_integrity, sender_integrity_key)
                                
                                if not is_valid:
                                    self.log(f"[{client_id}] Integrity check failed - possible tampering!", "WARNING")
                                    self.ids.detect_integrity_violation(address[0], {
                                        'client_id': client_id,
                                        'packet_number': audio_packet_count
                                    })
                                    continue
                                
                                self.log(f"[{client_id}] Received audio packet #{audio_packet_count} "
                                       f"({packet_size} bytes encrypted, {len(audio_data)} bytes audio, integrity verified)", "RECEIVE")
                                
                                # Broadcast to other clients (with new integrity checks for each)
                                recipients = self.broadcast_audio(audio_data, client_socket)
                                if recipients > 0:
                                    self.log(f"[{client_id}] Broadcasted to {recipients} client(s)", "SEND")
                            except Exception as decrypt_error:
                                # Decryption failure - possible eavesdropping or MITM
                                error_msg = str(decrypt_error)
                                if "tag" in error_msg.lower() or "authentication" in error_msg.lower():
                                    # GCM authentication failure - MITM attack
                                    self.ids.detect_authentication_failure(address[0], error_msg)
                                    self.log(f"[{client_id}] Authentication failure - possible MITM attack", "ALERT")
                                else:
                                    # General decryption failure - possible eavesdropping
                                    self.ids.detect_decryption_failure(address[0], error_msg)
                                    self.log(f"[{client_id}] Decryption failure - possible eavesdropping attempt", "ALERT")
                                raise
                    except Exception as e:
                        self.log(f"[{client_id}] Error processing audio: {e}", "ERROR")
                
                elif msg_type == 'T':  # Targeted audio data
                    try:
                        audio_packet_count += 1
                        packet_size = len(encrypted_data)
                        
                        # Parse recipient name from message
                        # Format: [2 bytes: name length][name bytes][encrypted audio]
                        if len(encrypted_data) < 2:
                            self.log(f"[{client_id}] Invalid targeted message format", "ERROR")
                            continue
                        
                        recipient_name_len = int.from_bytes(encrypted_data[:2], 'big')
                        if len(encrypted_data) < 2 + recipient_name_len:
                            self.log(f"[{client_id}] Invalid targeted message: incomplete recipient name", "ERROR")
                            continue
                        
                        recipient_name = encrypted_data[2:2+recipient_name_len].decode('utf-8', errors='ignore')
                        encrypted_audio = encrypted_data[2+recipient_name_len:]
                        
                        if not encrypted_audio:
                            self.log(f"[{client_id}] Invalid targeted message: no audio data", "ERROR")
                            continue
                        
                        # Get sender name
                        sender_name = self.client_names.get(client_socket, f"Client_{client_id}")
                        
                        # Decrypt audio
                        aes_key = self.client_keys.get(client_socket)
                        if aes_key:
                            try:
                                audio_with_integrity = decrypt_data(encrypted_audio, aes_key)
                                
                                # Verify integrity with sender's key
                                sender_integrity_key = aes_key[:16]
                                is_valid, audio_data = verify_integrity(audio_with_integrity, sender_integrity_key)
                                
                                if not is_valid:
                                    self.log(f"[{client_id}] Integrity check failed for targeted message - possible tampering!", "WARNING")
                                    self.ids.detect_integrity_violation(address[0], {
                                        'client_id': client_id,
                                        'packet_number': audio_packet_count,
                                        'recipient': recipient_name
                                    })
                                    continue
                                
                                audio_size = len(audio_data)
                                self.log(f"[{client_id}] Received targeted audio packet #{audio_packet_count} "
                                       f"from '{sender_name}' to '{recipient_name}' "
                                       f"({packet_size} bytes encrypted, {audio_size} bytes audio, integrity verified)", "RECEIVE")
                                
                                # Send to specific recipient (with new integrity check)
                                success = self.send_targeted_audio(audio_data, recipient_name, sender_name)
                                if success:
                                    self.log(f"[{client_id}] Sent targeted audio to '{recipient_name}'", "SEND")
                                else:
                                    self.log(f"[{client_id}] Failed to send targeted audio to '{recipient_name}' (client not found)", "WARNING")
                            except Exception as decrypt_error:
                                # Decryption failure - possible eavesdropping or MITM
                                error_msg = str(decrypt_error)
                                if "tag" in error_msg.lower() or "authentication" in error_msg.lower():
                                    # GCM authentication failure - MITM attack
                                    self.ids.detect_authentication_failure(address[0], error_msg)
                                    self.log(f"[{client_id}] Authentication failure - possible MITM attack", "ALERT")
                                else:
                                    # General decryption failure - possible eavesdropping
                                    self.ids.detect_decryption_failure(address[0], error_msg)
                                    self.log(f"[{client_id}] Decryption failure - possible eavesdropping attempt", "ALERT")
                                raise
                    except Exception as e:
                        self.log(f"[{client_id}] Error processing targeted audio: {e}", "ERROR")
        
        except Exception as e:
            self.log(f"[{client_id}] Error handling client: {e}", "ERROR")
        finally:
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            if client_socket in self.client_keys:
                del self.client_keys[client_socket]
            # Clean up client name mappings
            if client_socket in self.client_names:
                client_name = self.client_names[client_socket]
                del self.client_names[client_socket]
                if client_name in self.client_socket_map:
                    del self.client_socket_map[client_name]
            close_connection(client_socket)
            self.log(f"[{client_id}] Client disconnected. Active clients: {len(self.clients)}", "DISCONNECT")
    
    def broadcast_audio(self, audio_data, sender_socket):
        """Broadcast audio to all clients except the sender.
        
        Args:
            audio_data: Clean audio data (HMAC already verified and removed)
            sender_socket: Socket of the sender
        """
        disconnected_clients = []
        recipients = 0
        sender_name = self.client_names.get(sender_socket, "Unknown")
        
        for client in self.clients:
            if client != sender_socket:
                try:
                    # Add integrity check with recipient's key
                    recipient_aes_key = self.client_keys.get(client)
                    if recipient_aes_key:
                        recipient_integrity_key = recipient_aes_key[:16]
                        audio_with_integrity = add_integrity_check(audio_data, recipient_integrity_key)
                        
                        # Re-encrypt for recipient
                        encrypted_audio = encrypt_data(audio_with_integrity, recipient_aes_key)
                        send_message(client, 'A', encrypted_audio)
                        recipients += 1
                except Exception as e:
                    self.log(f"Error broadcasting to client: {e}", "ERROR")
                    disconnected_clients.append(client)
        
        # Remove disconnected clients
        for client in disconnected_clients:
            if client in self.clients:
                self.clients.remove(client)
            if client in self.client_keys:
                del self.client_keys[client]
        
        return recipients
    
    def send_targeted_audio(self, audio_data, recipient_name, sender_name):
        """Send audio to a specific client by name.
        
        Args:
            audio_data: Clean audio data (HMAC already verified and removed)
            recipient_name: Name of the recipient client
            sender_name: Name of the sender (for logging)
        
        Returns:
            bool: True if successfully sent, False if recipient not found
        """
        # Find recipient socket by name
        recipient_socket = self.client_socket_map.get(recipient_name)
        
        if not recipient_socket:
            self.log(f"Targeted audio: Recipient '{recipient_name}' not found", "WARNING")
            return False
        
        # Check if recipient is still connected
        if recipient_socket not in self.clients:
            self.log(f"Targeted audio: Recipient '{recipient_name}' is no longer connected", "WARNING")
            # Clean up stale mapping
            if recipient_name in self.client_socket_map:
                del self.client_socket_map[recipient_name]
            return False
        
        try:
            # Add integrity check with recipient's key
            recipient_aes_key = self.client_keys.get(recipient_socket)
            if not recipient_aes_key:
                self.log(f"Targeted audio: No encryption key for recipient '{recipient_name}'", "ERROR")
                return False
            
            recipient_integrity_key = recipient_aes_key[:16]
            audio_with_integrity = add_integrity_check(audio_data, recipient_integrity_key)
            
            # Re-encrypt for recipient
            encrypted_audio = encrypt_data(audio_with_integrity, recipient_aes_key)
            send_message(recipient_socket, 'A', encrypted_audio)
            self.log(f"Targeted audio: Sent from '{sender_name}' to '{recipient_name}'", "SEND")
            return True
        except Exception as e:
            self.log(f"Error sending targeted audio to '{recipient_name}': {e}", "ERROR")
            return False
    
    def stop(self):
        """Stop the server."""
        self.running = False
        self.log("Shutting down server...", "SHUTDOWN")
        if self.server_socket:
            close_connection(self.server_socket)
        for client in self.clients:
            close_connection(client)
        self.log("Server stopped", "SHUTDOWN")


def main():
    """Main server entry point."""
    server = VoiceServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()


if __name__ == "__main__":
    main()

