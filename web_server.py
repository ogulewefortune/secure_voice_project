#!/usr/bin/env python3
"""
Web server for secure voice communication.
Provides a web-based interface for audio recording and transmission.
"""

import socket
import threading
import base64
import json
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from src.config import DEFAULT_HOST, DEFAULT_PORT, TARGET_BITRATE, MIN_SNR_DB, SAMPLE_RATE_FOR_64KBPS, QUANTIZATION_BITS
from src.network_protocol import establish_connection, send_message, receive_message, close_connection
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

# Store web client connections
web_clients = {}

# Initialize IDS and register alert callback for web interface
ids = get_ids()

def handle_security_alert(alert):
    """Handle security alert and broadcast to all web clients."""
    alert_data = alert.to_dict()
    socketio.emit('security_alert', alert_data, broadcast=True)
    log(f"SECURITY ALERT: {alert}", "ALERT")

# Register alert callback
ids.register_alert_callback(handle_security_alert)

class WebVoiceClient:
    """Web client that connects to the voice server."""
    
    def __init__(self, socket_id, voice_server_host=DEFAULT_HOST, voice_server_port=DEFAULT_PORT):
        self.socket_id = socket_id
        self.voice_server_host = voice_server_host
        self.voice_server_port = voice_server_port
        self.socket = None
        self.aes_key = None
        self.private_key = None
        self.public_key = None
        self.connected = False
        self.running = False
        self.audio_packet_count = 0  # Track received audio packets
    
    def connect(self):
        """Connect to the voice server."""
        self.socket = establish_connection(self.voice_server_host, self.voice_server_port, is_server=False)
        if not self.socket:
            return False
        
        try:
            # Generate client key pair
            self.private_key, self.public_key = generate_key_pair()
            
            # Receive server public key
            msg_type, server_pub_key_bytes = receive_message(self.socket)
            if msg_type != 'K' or not server_pub_key_bytes:
                return False
            
            server_public_key = deserialize_public_key(server_pub_key_bytes)
            
            # Send client public key
            client_pub_key_bytes = serialize_public_key(self.public_key)
            send_message(self.socket, 'K', client_pub_key_bytes)
            
            # Receive salt
            msg_type, salt = receive_message(self.socket)
            if msg_type != 'S' or not salt:
                return False
            
            # Derive shared secret and AES key
            shared_secret = derive_shared_secret(self.private_key, server_public_key)
            self.aes_key, _ = derive_aes_key(shared_secret, salt)
            
            self.connected = True
            self.running = True
            self.audio_packet_count = 0  # Reset packet counter on new connection
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self.receive_audio_loop, daemon=True)
            receive_thread.start()
            
            return True
        
        except Exception as e:
            print(f"Error during key exchange: {e}")
            return False
    
    def send_audio(self, audio_data_base64, audio_format='webm'):
        """Send audio data to the voice server with compression and integrity checks."""
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
            
            # Send to server
            success = send_message(self.socket, 'A', encrypted_audio)
            if success:
                log(f"[Web Client {self.socket_id[:8]}] Sent audio packet to server ({encrypted_size} bytes)", "SEND")
            else:
                log(f"[Web Client {self.socket_id[:8]}] Failed to send audio", "ERROR")
            
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
    
    def receive_audio_loop(self):
        """Continuously receive audio from the voice server."""
        while self.running:
            try:
                msg_type, encrypted_data = receive_message(self.socket)
                if not msg_type or not encrypted_data:
                    break
                
                if msg_type == 'A' and self.aes_key:  # Audio data
                    try:
                        self.audio_packet_count += 1
                        encrypted_size = len(encrypted_data)
                        log(f"[Web Client {self.socket_id[:8]}] Received audio packet #{self.audio_packet_count} ({encrypted_size} bytes encrypted)", "RECEIVE")
                        
                        # Decrypt audio
                        try:
                            encrypted_audio_data = decrypt_data(encrypted_data, self.aes_key)
                            decrypted_size = len(encrypted_audio_data)
                            log(f"[Web Client {self.socket_id[:8]}] Decrypted: {encrypted_size} → {decrypted_size} bytes", "SECURITY")
                        except Exception as decrypt_error:
                            # Decryption failure - possible eavesdropping or MITM
                            error_msg = str(decrypt_error)
                            if "tag" in error_msg.lower() or "authentication" in error_msg.lower():
                                # GCM authentication failure - MITM attack
                                ids.detect_authentication_failure("server", error_msg)
                                log(f"[Web Client {self.socket_id[:8]}] Authentication failure - possible MITM attack", "ALERT")
                            else:
                                # General decryption failure - possible eavesdropping
                                ids.detect_decryption_failure("server", error_msg)
                                log(f"[Web Client {self.socket_id[:8]}] Decryption failure - possible eavesdropping attempt", "ALERT")
                            socketio.emit('audio_error', {
                                'message': 'Decryption failed - security threat detected!'
                            }, room=self.socket_id)
                            raise
                        
                        # Verify integrity
                        integrity_key = self.aes_key[:16]
                        is_valid, audio_data = verify_integrity(encrypted_audio_data, integrity_key)
                        
                        if not is_valid:
                            log(f"[Web Client {self.socket_id[:8]}] Warning: Audio integrity check failed - possible tampering!", "WARNING")
                            # Detect integrity violation
                            ids.detect_integrity_violation("server", {
                                'client_id': self.socket_id[:8],
                                'packet_number': self.audio_packet_count
                            })
                            socketio.emit('audio_error', {
                                'message': 'Audio integrity check failed - possible tampering detected!'
                            }, room=self.socket_id)
                            continue
                        
                        audio_size = len(audio_data)
                        log(f"[Web Client {self.socket_id[:8]}] Integrity verified ({audio_size} bytes)", "SECURITY")
                        
                        # Encode to base64 for web transmission
                        audio_base64 = base64.b64encode(audio_data).decode('utf-8')
                        
                        # Send to web client via SocketIO with packet information
                        socketio.emit('audio_received', {
                            'audio': audio_base64,
                            'format': 'pcm',
                            'verified': True,
                            'packet_number': self.audio_packet_count,
                            'encrypted_size': encrypted_size,
                            'decrypted_size': decrypted_size
                        }, room=self.socket_id)
                        log(f"[Web Client {self.socket_id[:8]}] Forwarded audio to web client", "SEND")
                    except Exception as e:
                        log(f"[Web Client {self.socket_id[:8]}] Error processing received audio: {e}", "ERROR")
                        socketio.emit('audio_error', {
                            'message': str(e)
                        }, room=self.socket_id)
            
            except Exception as e:
                if self.running:
                    print(f"Error receiving audio: {e}")
                break
        
        # Notify web client of disconnection
        socketio.emit('disconnected', {'reason': 'Server connection lost'}, room=self.socket_id)
        self.connected = False
    
    def disconnect(self):
        """Disconnect from the voice server."""
        self.running = False
        self.connected = False
        if self.socket:
            close_connection(self.socket)


@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@socketio.on('connect')
def handle_connect():
    """Handle web client connection."""
    log(f"Web client connected: {request.sid[:8]}...", "CONNECT")
    emit('connected', {'status': 'ok'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle web client disconnection."""
    log(f"Web client disconnected: {request.sid[:8]}...", "DISCONNECT")
    if request.sid in web_clients:
        web_clients[request.sid].disconnect()
        del web_clients[request.sid]


@socketio.on('connect_to_server')
def handle_connect_to_server(data):
    """Handle request to connect to voice server."""
    try:
        host = data.get('host', DEFAULT_HOST)
        port = data.get('port', DEFAULT_PORT)
        
        log(f"[{request.sid[:8]}] Connecting to voice server at {host}:{port}...", "CONNECT")
        client = WebVoiceClient(request.sid, host, port)
        if client.connect():
            web_clients[request.sid] = client
            log(f"[{request.sid[:8]}] Successfully connected to voice server", "CONNECT")
            emit('server_connected', {
                'status': 'connected',
                'host': host,
                'port': port
            })
        else:
            log(f"[{request.sid[:8]}] Failed to connect to voice server", "ERROR")
            emit('server_error', {'message': 'Failed to connect to voice server'})
    except Exception as e:
        emit('server_error', {'message': str(e)})


@socketio.on('send_audio')
def handle_send_audio(data):
    """Handle audio data from web client."""
    if request.sid in web_clients:
        client = web_clients[request.sid]
        audio_data = data.get('audio')
        if audio_data:
            success, snr_db, bitrate, processing_details = client.send_audio(audio_data)
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


@socketio.on('get_security_alerts')
def handle_get_security_alerts():
    """Handle request to get recent security alerts."""
    recent_alerts = ids.get_recent_alerts(limit=50)
    alerts_data = [alert.to_dict() for alert in recent_alerts]
    emit('security_alerts', {'alerts': alerts_data})


@socketio.on('get_security_stats')
def handle_get_security_stats():
    """Handle request to get security statistics."""
    stats = ids.get_statistics()
    emit('security_stats', stats)


if __name__ == '__main__':
    log("=" * 60)
    log("Secure Voice Communication - Web Server")
    log("=" * 60)
    log("Starting web server on http://localhost:5000")
    log("Open your browser and navigate to: http://localhost:5000")
    log("Make sure the voice server is running on port 8888")
    log("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

