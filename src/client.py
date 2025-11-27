"""
Client module for secure voice communication.
Handles client-side connection, audio capture, and encryption.
"""

import threading
import time
from src.config import DEFAULT_HOST, DEFAULT_PORT
from src.network_protocol import establish_connection, send_message, receive_message, close_connection
from src.crypto_utils import generate_key_pair, serialize_public_key, deserialize_public_key, derive_shared_secret, derive_aes_key, encrypt_data, decrypt_data
from src.audio_processor import AudioProcessor


class VoiceClient:
    """Client for secure voice communication."""
    
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.aes_key = None
        self.audio_processor = AudioProcessor()
        self.running = False
    
    def connect(self):
        """Connect to the server."""
        self.socket = establish_connection(self.host, self.port, is_server=False)
        if not self.socket:
            print("Failed to connect to server")
            return False
        
        try:
            # Generate client key pair
            self.private_key, self.public_key = generate_key_pair()
            
            # Receive server public key
            msg_type, server_pub_key_bytes = receive_message(self.socket)
            if msg_type != 'K' or not server_pub_key_bytes:
                print("Failed to receive server public key")
                return False
            
            server_public_key = deserialize_public_key(server_pub_key_bytes)
            
            # Send client public key
            client_pub_key_bytes = serialize_public_key(self.public_key)
            send_message(self.socket, 'K', client_pub_key_bytes)
            
            # Receive salt
            msg_type, salt = receive_message(self.socket)
            if msg_type != 'S' or not salt:
                print("Failed to receive salt")
                return False
            
            # Derive shared secret and AES key
            shared_secret = derive_shared_secret(self.private_key, server_public_key)
            self.aes_key, _ = derive_aes_key(shared_secret, salt)
            
            print("Connected to server and secure channel established!")
            return True
        
        except Exception as e:
            print(f"Error during key exchange: {e}")
            return False
    
    def start(self):
        """Start the client."""
        if not self.connect():
            return
        
        self.running = True
        
        # Start audio capture and playback
        self.audio_processor.start_capture()
        self.audio_processor.start_playback()
        
        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_audio, daemon=True)
        receive_thread.start()
        
        # Start sending thread
        send_thread = threading.Thread(target=self.send_audio, daemon=True)
        send_thread.start()
        
        print("Voice communication started. Press Ctrl+C to stop.")
        
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nShutting down client...")
            self.stop()
    
    def send_audio(self):
        """Continuously capture and send audio."""
        while self.running:
            try:
                audio_data = self.audio_processor.capture_audio()
                if audio_data and self.aes_key:
                    # Encrypt audio
                    encrypted_audio = encrypt_data(audio_data, self.aes_key)
                    # Send to server
                    send_message(self.socket, 'A', encrypted_audio)
                time.sleep(0.01)  # Small delay to prevent CPU overload
            except Exception as e:
                if self.running:
                    print(f"Error sending audio: {e}")
                break
    
    def receive_audio(self):
        """Continuously receive and play audio."""
        while self.running:
            try:
                msg_type, encrypted_data = receive_message(self.socket)
                if not msg_type or not encrypted_data:
                    break
                
                if msg_type == 'A' and self.aes_key:  # Audio data
                    try:
                        # Decrypt audio
                        audio_data = decrypt_data(encrypted_data, self.aes_key)
                        # Play audio
                        self.audio_processor.play_audio(audio_data)
                    except Exception as e:
                        print(f"Error processing received audio: {e}")
            
            except Exception as e:
                if self.running:
                    print(f"Error receiving audio: {e}")
                break
    
    def stop(self):
        """Stop the client."""
        self.running = False
        self.audio_processor.cleanup()
        if self.socket:
            close_connection(self.socket)
        print("Client stopped")


def main():
    """Main client entry point."""
    client = VoiceClient()
    try:
        client.start()
    except Exception as e:
        print(f"Client error: {e}")
        client.stop()


if __name__ == "__main__":
    main()

