"""
Test-only VoiceServer class for security testing.
This is a minimal TCP server implementation used only for testing security features.
The production server is integrated into web_server.py via SocketIO.
"""

import socket
import threading
import requests
from src.config import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_WEB_PORT
from src.network_protocol import establish_connection, send_message, receive_message, close_connection
from src.crypto_utils import generate_key_pair, serialize_public_key, deserialize_public_key, derive_shared_secret, derive_aes_key, encrypt_data, decrypt_data
from src.intrusion_detection import get_ids


class VoiceServer:
    """Test-only TCP server for security testing."""
    
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []  # List of connected client sockets
        self.client_keys = {}  # Map socket → AES key
        self.client_names = {}  # Map socket → client name
        self.running = False
        self.private_key, self.public_key = generate_key_pair()
        self.ids = get_ids()
        self.web_server_url = f"http://localhost:{DEFAULT_WEB_PORT}"
        
        # Register alert callback to send alerts to web server
        self.ids.register_alert_callback(self._send_alert_to_web_server)
    
    def start(self):
        """Start the server."""
        try:
            self.server_socket = establish_connection(self.host, self.port, is_server=True)
            if not self.server_socket:
                print(f"Failed to start server on {self.host}:{self.port}")
                return
            
            self.running = True
            print(f"Test server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"Client connected from {address}")
                    self.clients.append(client_socket)
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.error:
                    if self.running:
                        break
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, address):
        """Handle a client connection."""
        try:
            # 1. Send server public key
            server_pub_key_bytes = serialize_public_key(self.public_key)
            send_message(client_socket, 'K', server_pub_key_bytes)
            
            # 2. Receive client public key
            msg_type, client_pub_key_bytes = receive_message(client_socket)
            if msg_type != 'K' or not client_pub_key_bytes:
                print(f"Invalid key exchange from {address}")
                return
            
            client_public_key = deserialize_public_key(client_pub_key_bytes)
            
            # 3. Derive shared secret
            shared_secret = derive_shared_secret(self.private_key, client_public_key)
            
            # 4. Derive AES key
            aes_key, salt = derive_aes_key(shared_secret)
            self.client_keys[client_socket] = aes_key
            
            # 5. Send salt to client
            send_message(client_socket, 'S', salt)
            
            # 6. Receive client name (optional)
            msg_type, name_data = receive_message(client_socket)
            if msg_type == 'N':
                client_name = name_data.decode('utf-8', errors='ignore')
                self.client_names[client_socket] = client_name
                print(f"Client {address} registered as '{client_name}'")
            
            # 7. Handle audio messages
            while self.running:
                msg_type, data = receive_message(client_socket)
                if not msg_type:
                    break
                
                if msg_type == 'A':
                    # Broadcast audio to other clients
                    self.broadcast_audio(data, client_socket)
                elif msg_type == 'T':
                    # Targeted audio (not implemented in test server)
                    pass
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            # Clean up
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            if client_socket in self.client_keys:
                del self.client_keys[client_socket]
            if client_socket in self.client_names:
                del self.client_names[client_socket]
            close_connection(client_socket)
            print(f"Client {address} disconnected")
    
    def broadcast_audio(self, audio_data, sender_socket):
        """Broadcast audio to all other clients."""
        recipients = 0
        for client in self.clients:
            if client != sender_socket and client in self.client_keys:
                # Re-encrypt for each client with their own key
                aes_key = self.client_keys[client]
                encrypted_audio = encrypt_data(audio_data, aes_key)
                send_message(client, 'A', encrypted_audio)
                recipients += 1
        return recipients
    
    def _send_alert_to_web_server(self, alert):
        """Send security alert to web server to display on website."""
        try:
            alert_data = alert.to_dict()
            # Try to send alert to web server via HTTP endpoint
            try:
                response = requests.post(
                    f"{self.web_server_url}/api/security_alert",
                    json=alert_data,
                    timeout=1
                )
                if response.status_code == 200:
                    print(f"[TEST SERVER] Alert sent to web server: {alert}")
            except (requests.exceptions.RequestException, Exception):
                # Web server might not be running or endpoint doesn't exist yet
                # That's okay - the alert is still logged
                pass
        except Exception as e:
            print(f"[TEST SERVER] Error sending alert to web server: {e}")
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        # Close all client connections
        for client in self.clients[:]:
            close_connection(client)
        self.clients.clear()
        self.client_keys.clear()
        self.client_names.clear()


def main():
    """Main entry point for test server."""
    server = VoiceServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()

