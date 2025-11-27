#!/usr/bin/env python3
"""
Web server for secure voice communication.
Provides a web-based interface for audio recording and transmission.
"""

import socket
import subprocess
import threading
import base64
import json
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from src.config import DEFAULT_HOST, DEFAULT_PORT, TARGET_BITRATE, MIN_SNR_DB, SAMPLE_RATE_FOR_64KBPS, QUANTIZATION_BITS, DEFAULT_WEB_PORT
from src.crypto_utils import generate_key_pair, serialize_public_key, deserialize_public_key, derive_shared_secret, derive_aes_key, encrypt_data, decrypt_data
from src.audio_compression import compress_to_64kbps, calculate_snr, add_integrity_check, verify_integrity
from src.intrusion_detection import get_ids, ThreatType

def log(message, level="INFO"):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-voice-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store web client connections - now handles everything via SocketIO
web_clients = {}

# Server key pair (shared by all clients)
server_private_key, server_public_key = generate_key_pair()

# Initialize IDS and register alert callback for web interface
ids = get_ids()

def handle_security_alert(alert):
    """Handle security alert and broadcast to all web clients."""
    try:
        alert_data = alert.to_dict()
        log(f"SECURITY ALERT: {alert}", "ALERT")
        log(f"Broadcasting security alert to web clients: {alert_data}", "ALERT")
        # Emit to all connected web clients
        socketio.emit('security_alert', alert_data)
        log(f"Security alert emitted successfully", "ALERT")
    except Exception as e:
        log(f"Error handling security alert: {e}", "ERROR")
        import traceback
        traceback.print_exc()

# Register alert callback
ids.register_alert_callback(handle_security_alert)

class WebVoiceClient:
    """Web client - now handles everything via SocketIO, no separate TCP connection."""
    
    def __init__(self, socket_id, client_name=None):
        self.socket_id = socket_id
        self.client_name = client_name or f"Client_{socket_id[:8]}"
        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.connected = False
        self.audio_packet_count = 0  # Track received audio packets
    
    def setup_encryption(self, client_public_key_bytes):
        """Set up encryption with client's public key."""
        try:
            # Deserialize client public key
            client_public_key = deserialize_public_key(client_public_key_bytes)
            
            # Derive shared secret and AES key
            shared_secret = derive_shared_secret(server_private_key, client_public_key)
            self.aes_key, salt = derive_aes_key(shared_secret)
            
            # Store client's public key for reference
            self.public_key = client_public_key
            
            return salt
        except Exception as e:
            log(f"[Web Client {self.socket_id[:8]}] Error setting up encryption: {e}", "ERROR")
            return None
    
    def send_audio(self, audio_data_base64, audio_format='webm', recipient_name=None):
        """Send audio data to the voice server with compression and integrity checks.
        
        Args:
            audio_data_base64: Base64 encoded audio data
            audio_format: Audio format (default: 'webm')
            recipient_name: Optional recipient name for targeted sending. If None, broadcasts to all.
        """
        if not self.connected or not self.aes_key:
            return False, None, None, None
        
        try:
            # Decode base64 audio data
            audio_data = base64.b64decode(audio_data_base64)
            original_size = len(audio_data)
            log(f"[Web Client {self.socket_id[:8]}] Processing audio: {original_size} bytes", "PROCESS")
            
            # Convert to numpy array for processing
            try:
                audio_array = np.frombuffer(audio_data, dtype=np.int16)
            except:
                audio_array = np.frombuffer(audio_data[:len(audio_data)//2*2], dtype=np.int16)
            
            # Compress to 64 Kbps and calculate SNR
            compressed_audio, snr_db, bitrate = compress_to_64kbps(
                audio_array, 
                sample_rate=SAMPLE_RATE_FOR_64KBPS,
                bits=QUANTIZATION_BITS
            )
            
            compressed_size = len(compressed_audio.tobytes())
            compression_ratio = (1 - compressed_size / original_size) * 100 if original_size > 0 else 0
            
            # Verify SNR meets requirement
            if snr_db < MIN_SNR_DB:
                log(f"[Web Client {self.socket_id[:8]}] Warning: SNR {snr_db:.2f}dB below requirement of {MIN_SNR_DB}dB", "WARNING")
            else:
                log(f"[Web Client {self.socket_id[:8]}] SNR: {snr_db:.2f}dB (meets ≥{MIN_SNR_DB}dB requirement)", "QUALITY")
            
            # Format compression ratio - show reduction or increase
            if compression_ratio >= 0:
                compression_text = f"{compression_ratio:.1f}% reduction"
            else:
                compression_text = f"{abs(compression_ratio):.1f}% increase"
            log(f"[Web Client {self.socket_id[:8]}] Compression: {original_size} → {compressed_size} bytes ({compression_text})", "COMPRESS")
            log(f"[Web Client {self.socket_id[:8]}] Bitrate: {bitrate/1000:.1f} Kbps (target: {TARGET_BITRATE/1000} Kbps)", "QUALITY")
            
            # Convert back to bytes
            # If it's uint8, it's already 1 byte per sample (compressed)
            # If it's int16, convert to bytes (2 bytes per sample)
            audio_bytes = compressed_audio.tobytes()
            
            # Add integrity check (HMAC)
            integrity_key = self.aes_key[:16]
            audio_with_integrity = add_integrity_check(audio_bytes, integrity_key)
            log(f"[Web Client {self.socket_id[:8]}] Added HMAC integrity check", "SECURITY")
            
            # Encrypt audio
            encrypted_audio = encrypt_data(audio_with_integrity, self.aes_key)
            encrypted_size = len(encrypted_audio)
            log(f"[Web Client {self.socket_id[:8]}] Encrypted: {compressed_size} → {encrypted_size} bytes (AES-256-GCM)", "SECURITY")
            
            # Broadcast to other clients via SocketIO (no TCP needed!)
            encrypted_audio_base64 = base64.b64encode(encrypted_audio).decode('utf-8')
            
            if recipient_name:
                # Targeted sending to specific client
                target_client = None
                for sid, client in web_clients.items():
                    if client.client_name == recipient_name and client.connected:
                        target_client = sid
                        break
                
                if target_client:
                    socketio.emit('audio_received', {
                        'audio': encrypted_audio_base64,  # Encrypted audio
                        'format': 'pcm',
                        'verified': True,
                        'packet_number': 0,  # Will be set by receiver
                        'encrypted_size': encrypted_size,
                        'decrypted_size': compressed_size,
                        'sender_name': self.client_name,
                        'is_encrypted': True,
                        'server_ip': get_local_ip()
                    }, room=target_client)
                    log(f"[Web Client {self.socket_id[:8]}] Sent targeted audio to: {recipient_name}", "SEND")
                    success = True
                else:
                    log(f"[Web Client {self.socket_id[:8]}] Target client not found: {recipient_name}", "ERROR")
                    success = False
            else:
                # Broadcast to all other connected clients
                recipients = 0
                for sid, client in web_clients.items():
                    if sid != self.socket_id and client.connected and client.aes_key:
                        # Re-encrypt for each recipient with their key
                        recipient_integrity_key = client.aes_key[:16]
                        recipient_audio_with_integrity = add_integrity_check(audio_bytes, recipient_integrity_key)
                        recipient_encrypted = encrypt_data(recipient_audio_with_integrity, client.aes_key)
                        recipient_encrypted_base64 = base64.b64encode(recipient_encrypted).decode('utf-8')
                        
                        socketio.emit('audio_received', {
                            'audio': recipient_encrypted_base64,  # Encrypted with recipient's key
                            'format': 'pcm',
                            'verified': True,
                            'packet_number': client.audio_packet_count + 1,
                            'encrypted_size': len(recipient_encrypted),
                            'decrypted_size': compressed_size,
                            'sender_name': self.client_name,
                            'is_encrypted': True,
                            'server_ip': get_local_ip()
                        }, room=sid)
                        recipients += 1
                
                log(f"[Web Client {self.socket_id[:8]}] Broadcasted to {recipients} client(s)", "SEND")
                success = recipients > 0
            
            # Return success status and processing details
            processing_details = {
                'original_size': original_size,
                'compressed_size': compressed_size,
                'compression_ratio': compression_ratio,
                'encrypted_size': encrypted_size,
                'snr_db': snr_db,
                'bitrate': bitrate,
                'snr_meets_requirement': snr_db >= MIN_SNR_DB if snr_db is not None else False
            }
            
            return success, snr_db, bitrate, processing_details
        except Exception as e:
            log(f"[Web Client {self.socket_id[:8]}] Error sending audio: {e}", "ERROR")
            return False, None, None, None
    
    def disconnect(self):
        """Disconnect client."""
        self.connected = False


@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    """Handle web client connection."""
    log(f"Web client connected: {request.sid[:8]}...", "CONNECT")
    server_ip = get_local_ip()
    emit('connected', {'status': 'ok', 'server_ip': server_ip})
    # Also send server info - voice server is integrated, so use localhost
    emit('server_info', {'server_ip': 'localhost', 'port': DEFAULT_PORT, 'integrated': True})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle web client disconnection."""
    log(f"Web client disconnected: {request.sid[:8]}...", "DISCONNECT")
    was_connected = request.sid in web_clients and web_clients[request.sid].connected
    if request.sid in web_clients:
        web_clients[request.sid].disconnect()
        del web_clients[request.sid]
        # Broadcast client count update if they were connected to voice server
        if was_connected:
            broadcast_client_count_update()


def broadcast_client_count_update():
    """Broadcast updated client count to all web clients."""
    # Count clients connected to voice server
    connected_count = len([c for c in web_clients.values() if c.connected])
    client_list = [{'name': c.client_name, 'id': c.socket_id[:8]} for c in web_clients.values() if c.connected]
    
    log(f"Broadcasting client count update: {connected_count} clients connected. Clients: {[c['name'] for c in client_list]}", "INFO")
    
    # Broadcast to all web clients
    socketio.emit('client_count_update', {
        'count': connected_count,
        'clients': client_list
    })
    
    log(f"Client count update event emitted to all clients", "INFO")


@socketio.on('connect_to_server')
def handle_connect_to_server(data):
    """Handle request to connect - now everything is via SocketIO, no separate server needed!"""
    try:
        client_name = data.get('client_name', f"Client_{request.sid[:8]}")
        
        log(f"[{request.sid[:8]}] Client connecting as '{client_name}'...", "CONNECT")
        
        # Create client instance
        client = WebVoiceClient(request.sid, client_name=client_name)
        web_clients[request.sid] = client
        
        # Send server public key to client for key exchange
        server_pub_key_bytes = serialize_public_key(server_public_key)
        server_pub_key_base64 = base64.b64encode(server_pub_key_bytes).decode('utf-8')
        
        emit('server_public_key', {
            'public_key': server_pub_key_base64
        })
        
        log(f"[{request.sid[:8]}] Sent server public key, waiting for client public key...", "KEY_EXCHANGE")
        
    except Exception as e:
        error_msg = str(e)
        log(f"[{request.sid[:8]}] Connection error: {error_msg}", "ERROR")
        emit('server_error', {
            'message': f'Connection error: {error_msg}',
            'error': error_msg
        })


@socketio.on('client_public_key')
def handle_client_public_key(data):
    """Handle client's public key and complete key exchange."""
    try:
        if request.sid not in web_clients:
            emit('server_error', {'message': 'Client not found'})
            return
        
        client = web_clients[request.sid]
        public_key_data = data.get('public_key', '')
        
        # If placeholder, generate client keys on server side
        # (In production, browser would generate keys using Web Crypto API)
        if public_key_data == 'placeholder':
            # Generate client key pair on server
            client.private_key, client.public_key = generate_key_pair()
            client_public_key_bytes = serialize_public_key(client.public_key)
        else:
            # Client sent actual public key
            client_public_key_bytes = base64.b64decode(public_key_data)
            client.public_key = deserialize_public_key(client_public_key_bytes)
        
        # Set up encryption
        salt = client.setup_encryption(serialize_public_key(client.public_key))
        if not salt:
            emit('server_error', {'message': 'Failed to set up encryption'})
            return
        
        # Send salt to client
        salt_base64 = base64.b64encode(salt).decode('utf-8')
        emit('server_salt', {
            'salt': salt_base64
        })
        
        client.connected = True
        log(f"[{request.sid[:8]}] Key exchange complete, client '{client.client_name}' connected", "CONNECT")
        
        emit('server_connected', {
            'status': 'connected',
            'client_name': client.client_name
        })
        
        # Broadcast client count update
        broadcast_client_count_update()
        
    except Exception as e:
        log(f"[{request.sid[:8]}] Key exchange error: {e}", "ERROR")
        emit('server_error', {'message': f'Key exchange failed: {str(e)}'})


@socketio.on('client_name')
def handle_client_name(data):
    """Handle client name registration."""
    try:
        if request.sid in web_clients:
            client = web_clients[request.sid]
            name = data.get('name', client.client_name)
            
            # Handle duplicate names
            original_name = name
            counter = 1
            while any(c.client_name == name for c in web_clients.values() if c.socket_id != request.sid):
                name = f"{original_name}_{counter}"
                counter += 1
            
            client.client_name = name
            log(f"[{request.sid[:8]}] Client registered as: {name}", "INFO")
            broadcast_client_count_update()
    except Exception as e:
        log(f"[{request.sid[:8]}] Error registering name: {e}", "ERROR")


@socketio.on('send_audio')
def handle_send_audio(data):
    """Handle audio data from web client - broadcast to other clients via SocketIO."""
    if request.sid in web_clients:
        client = web_clients[request.sid]
        if not client.connected:
            emit('audio_error', {'message': 'Not connected'})
            return
            
        audio_data = data.get('audio')
        recipient_name = data.get('recipient')  # Optional recipient name
        if audio_data:
            success, snr_db, bitrate, processing_details = client.send_audio(audio_data, recipient_name=recipient_name)
            if success and processing_details:
                # Convert numpy types to native Python types for JSON serialization
                snr_value = float(snr_db) if snr_db is not None else None
                bitrate_value = int(bitrate) if bitrate is not None else None
                snr_meets = bool(snr_value >= MIN_SNR_DB) if snr_value is not None else False
                
                emit('audio_sent', {
                    'status': 'ok',
                    'snr_db': snr_value,
                    'bitrate': bitrate_value,
                    'snr_meets_requirement': snr_meets,
                    'processing_details': {
                        'original_size': int(processing_details['original_size']),
                        'compressed_size': int(processing_details['compressed_size']),
                        'compression_ratio': float(processing_details['compression_ratio']),
                        'encrypted_size': int(processing_details['encrypted_size']),
                        'snr_db': snr_value,
                        'bitrate': bitrate_value,
                        'snr_meets_requirement': snr_meets
                    }
                })
            elif success:
                # Fallback if processing_details is None
                snr_value = float(snr_db) if snr_db is not None else None
                bitrate_value = int(bitrate) if bitrate is not None else None
                snr_meets = bool(snr_value >= MIN_SNR_DB) if snr_value is not None else False
                
                emit('audio_sent', {
                    'status': 'ok',
                    'snr_db': snr_value,
                    'bitrate': bitrate_value,
                    'snr_meets_requirement': snr_meets
                })
            else:
                emit('audio_error', {'message': 'Failed to send audio'})


@socketio.on('disconnect_from_server')
def handle_disconnect_from_server():
    """Handle request to disconnect from voice server."""
    if request.sid in web_clients:
        web_clients[request.sid].disconnect()
        del web_clients[request.sid]
        emit('server_disconnected', {'status': 'disconnected'})
        # Broadcast client count update to remaining clients
        broadcast_client_count_update()


@socketio.on('get_client_count')
def handle_get_client_count():
    """Handle request to get current client count."""
    connected_count = len([c for c in web_clients.values() if c.connected])
    client_list = [{'name': c.client_name, 'id': c.socket_id[:8]} for c in web_clients.values() if c.connected]
    log(f"[{request.sid[:8]}] Client requested count: {connected_count} clients", "INFO")
    emit('client_count_update', {
        'count': connected_count,
        'clients': client_list
    })
    log(f"[{request.sid[:8]}] Sent client count update: {connected_count} clients", "INFO")


@socketio.on('get_security_alerts')
def handle_get_security_alerts():
    """Handle request to get recent security alerts."""
    try:
        recent_alerts = ids.get_recent_alerts(limit=50)
        alerts_data = [alert.to_dict() for alert in recent_alerts]
        log(f"Sending {len(alerts_data)} recent security alerts to web client", "INFO")
        emit('security_alerts', {'alerts': alerts_data})
        
        # Also emit each alert individually to trigger UI updates
        for alert_dict in alerts_data:
            emit('security_alert', alert_dict)
    except Exception as e:
        log(f"Error getting security alerts: {e}", "ERROR")
        emit('security_alerts', {'alerts': []})


@socketio.on('get_security_stats')
def handle_get_security_stats():
    """Handle request to get security statistics."""
    stats = ids.get_statistics()
    emit('security_stats', stats)


@socketio.on('decrypt_audio')
def handle_decrypt_audio(data):
    """Handle request to decrypt encrypted audio."""
    try:
        message_id = data.get('message_id')
        encrypted_audio_base64 = data.get('audio')
        server_ip = data.get('server_ip')
        
        log(f"[{request.sid[:8]}] Decrypt audio request for message {message_id} from server {server_ip}", "INFO")
        
        if request.sid in web_clients:
            client = web_clients[request.sid]
            if client.connected and client.aes_key:
                try:
                    # Decode the encrypted audio
                    encrypted_audio = base64.b64decode(encrypted_audio_base64)
                    
                    # Decrypt using client's AES key
                    encrypted_audio_data = decrypt_data(encrypted_audio, client.aes_key)
                    
                    # Verify integrity
                    integrity_key = client.aes_key[:16]
                    is_valid, audio_data = verify_integrity(encrypted_audio_data, integrity_key)
                    
                    if not is_valid:
                        log(f"[{request.sid[:8]}] Integrity check failed during decryption", "WARNING")
                        emit('audio_decrypted', {
                            'message_id': message_id,
                            'status': 'error',
                            'message': 'Integrity check failed - audio may have been tampered with'
                        })
                        return
                    
                    # Encode decrypted audio to base64
                    decrypted_audio_base64 = base64.b64encode(audio_data).decode('utf-8')
                    
                    emit('audio_decrypted', {
                        'message_id': message_id,
                        'decrypted_audio': decrypted_audio_base64,
                        'status': 'success',
                        'note': 'Audio decrypted successfully',
                        'server_ip': server_ip
                    })
                    log(f"[{request.sid[:8]}] Audio decrypted successfully for message {message_id}", "INFO")
                except Exception as decrypt_error:
                    error_msg = str(decrypt_error)
                    log(f"[{request.sid[:8]}] Decryption error: {error_msg}", "ERROR")
                    emit('audio_decrypted', {
                        'message_id': message_id,
                        'status': 'error',
                        'message': f'Decryption failed: {error_msg}'
                    })
            else:
                emit('audio_decrypted', {
                    'message_id': message_id,
                    'status': 'error',
                    'message': 'Not connected to voice server or no encryption key'
                })
        else:
            emit('audio_decrypted', {
                'message_id': message_id,
                'status': 'error',
                'message': 'Client not found'
            })
    except Exception as e:
        log(f"[{request.sid[:8]}] Error handling decrypt request: {e}", "ERROR")
        emit('audio_decrypted', {
            'message_id': data.get('message_id', 'unknown'),
            'status': 'error',
            'message': str(e)
        })


def get_local_ip():
    """Get the local IP address of this machine (cross-platform)."""
    try:
        # Connect to a remote address to determine local IP
        # Try multiple common gateway addresses
        for gateway in ['8.8.8.8', '1.1.1.1', '10.254.254.254']:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((gateway, 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith('127.'):
                    return ip
            except Exception:
                continue
        return '127.0.0.1'
    except Exception:
        try:
            import platform
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip == '127.0.0.1' or ip.startswith('127.'):
                # Try alternative method for Windows/Linux
                if platform.system() == 'Windows':
                    # Windows: use ipconfig equivalent
                    import subprocess
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                    if result.returncode == 0:
                        # Parse IPv4 address from ipconfig output
                        import re
                        matches = re.findall(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                        if matches:
                            # Return first non-loopback address
                            for match in matches:
                                if not match.startswith('127.'):
                                    return match
                else:
                    # macOS: use ipconfig getifaddr
                    import platform
                    if platform.system() == 'Darwin':  # macOS
                        # Try Wi-Fi interface (en0) first, then Ethernet (en1)
                        for interface in ['en0', 'en1', 'en2']:
                            result = subprocess.run(['ipconfig', 'getifaddr', interface], capture_output=True, text=True)
                            if result.returncode == 0 and result.stdout.strip():
                                ip = result.stdout.strip()
                                if not ip.startswith('127.'):
                                    return ip
                        # Fallback: use ifconfig
                        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                        if result.returncode == 0:
                            import re
                            # Look for inet addresses (not loopback)
                            matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                            for match in matches:
                                if not match.startswith('127.'):
                                    return match
                    else:
                        # Linux: use hostname -I
                        import subprocess
                        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                        if result.returncode == 0 and result.stdout.strip():
                            ip = result.stdout.strip().split()[0]
                            if not ip.startswith('127.'):
                                return ip
            return ip
        except Exception:
            return '127.0.0.1'


if __name__ == '__main__':
    local_ip = get_local_ip()
    
    log("")
    log("=" * 70)
    log(" " * 20 + "SECURE VOICE COMMUNICATION SERVER")
    log("=" * 70)
    log("")
    log("SERVER IP ADDRESS FOR OTHER DEVICES:")
    log(" " * 10 + f"  >>>  {local_ip}  <<<")
    log("")
    log("=" * 70)
    log("SINGLE SERVER (All-in-One via SocketIO):")
    log(f"  Web Interface:  http://{local_ip}:{DEFAULT_WEB_PORT}")
    log(f"  Voice Communication: Integrated (via SocketIO)")
    log("")
    log("=" * 70)
    log("TO CONNECT FROM ANOTHER DEVICE:")
    log(f"  1. Open browser on the other device")
    log(f"  2. Go to: http://{local_ip}:{DEFAULT_WEB_PORT}")
    log(f"  3. Enter your name and click 'Connect'")
    log("")
    log("NOTE: Everything runs on ONE server - just run this file!")
    log("")
    log("IMPORTANT - macOS Firewall:")
    log("  If devices can't connect, check macOS Firewall:")
    log("  System Settings > Network > Firewall > Options")
    log("  Allow incoming connections for Python, or disable firewall")
    log(f"  Make sure port {DEFAULT_WEB_PORT} is not blocked")
    log("")
    log("Press Ctrl+C to stop the server")
    log("=" * 70)
    log("")
    socketio.run(app, host='0.0.0.0', port=DEFAULT_WEB_PORT, debug=False, allow_unsafe_werkzeug=True)

