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
import os
import numpy as np
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
from src.config import DEFAULT_HOST, DEFAULT_PORT, TARGET_BITRATE, MIN_SNR_DB, SAMPLE_RATE_FOR_64KBPS, QUANTIZATION_BITS, DEFAULT_WEB_PORT
from src.crypto_utils import (
    generate_rsa_key_pair, serialize_public_key, deserialize_public_key,
    create_session_key_bundle, encrypt_session_keys, decrypt_session_keys,
    generate_session_keys, create_secure_packet, verify_secure_packet,
    encrypt_data, decrypt_data  # Legacy compatibility
)
from src.audio_processor import AudioProcessor
from src.error_correction import ErrorCorrection
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

# Store original audio for each message (message_id -> original_audio_base64)
# This allows us to return the true original audio when decrypting, not the decompressed compressed audio
original_audio_store = {}

# Session management: track active sessions and participants
# Format: {session_id: {'host': socket_id, 'participants': [socket_id, ...], 'created': timestamp}}
active_sessions = {}
# Track which clients are in which sessions: {socket_id: session_id}
client_sessions = {}

# Server RSA key pair (shared by all clients)
server_private_key, server_public_key = generate_rsa_key_pair()

# Initialize audio processor and error correction (shared instances)
audio_processor = AudioProcessor(sample_rate=SAMPLE_RATE_FOR_64KBPS, bits=16)
error_correction = ErrorCorrection(nsym=32)  # RS(255, 223) - 14% overhead

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
        self.session_key = None  # AES-256 session key
        self.hmac_key = None     # HMAC key
        self.client_public_key = None  # Client's RSA public key
        self.connected = False
        self.audio_packet_count = 0  # Track sent audio packets (sequence number)
        self.expected_sequence = 0  # Track received sequence numbers
        self.session_id = None  # Current session ID if in a call
    
    def setup_encryption(self, client_public_key_bytes):
        """
        Set up encryption using RSA session key exchange.
        Server generates session keys and encrypts them with client's RSA public key.
        """
        try:
            # Deserialize client's RSA public key
            self.client_public_key = deserialize_public_key(client_public_key_bytes)
            
            # Generate session keys (AES + HMAC)
            self.session_key, self.hmac_key = generate_session_keys()
            
            # Create key bundle
            key_bundle = create_session_key_bundle(self.session_key, self.hmac_key)
            
            # Encrypt session keys with client's RSA public key
            encrypted_bundle = encrypt_session_keys(key_bundle, self.client_public_key)
            
            log(f"[Web Client {self.socket_id[:8]}] Session keys generated and encrypted with client's RSA public key", "SECURITY")
            
            # Return encrypted bundle (client will decrypt with their private key)
            return base64.b64encode(encrypted_bundle).decode('utf-8')
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
        if not self.connected or not self.session_key:
            return False, None, None, None
        
        try:
            # Decode base64 audio data
            audio_data = base64.b64decode(audio_data_base64)
            original_size = len(audio_data)
            log(f"[Web Client {self.socket_id[:8]}] Processing audio: {original_size} bytes", "PROCESS")
            
            # Convert to numpy array for processing (int16 PCM)
            try:
                audio_array = np.frombuffer(audio_data, dtype=np.int16)
            except:
                audio_array = np.frombuffer(audio_data[:len(audio_data)//2*2], dtype=np.int16)
            
            # Store original audio (int16) - this is the ACTUAL original audio before any processing
            # We send this with the encrypted message so clients can play the original audio directly
            # Use little-endian byte order for JavaScript compatibility
            original_bytes = audio_array.astype('<i2').tobytes()  # '<i2' = little-endian int16
            original_decompressed_audio_base64 = base64.b64encode(original_bytes).decode('utf-8')
            log(f"[Web Client {self.socket_id[:8]}] Original audio stored: {len(original_bytes)} bytes (int16, pristine quality)", "AUDIO")
            
            # Processing Pipeline: Filter → ADC → ADPCM → Reed-Solomon
            # Step 1: Process for transmission (Filter → ADC → ADPCM compression)
            # Convert int16 to normalized float for processing
            audio_normalized = audio_array.astype(np.float32) / 32768.0
            compressed_adpcm, num_samples = audio_processor.process_for_transmission(audio_normalized)
            
            # Step 2: Apply Reed-Solomon error correction
            ec_data = error_correction.encode(compressed_adpcm)
            
            # Calculate metrics
            original_pcm_size = len(original_bytes)
            adpcm_size = len(compressed_adpcm)
            ec_size = len(ec_data)
            compression_ratio = (1 - adpcm_size / original_pcm_size) * 100 if original_pcm_size > 0 else 0
            
            # Calculate bitrate (after error correction)
            bitrate = (ec_size * 8 * SAMPLE_RATE_FOR_64KBPS) / num_samples / 1000  # Kbps
            
            log(f"[Web Client {self.socket_id[:8]}] Audio processing: {original_pcm_size} → {adpcm_size} bytes (ADPCM, 4:1) → {ec_size} bytes (Reed-Solomon)", "PROCESS")
            log(f"[Web Client {self.socket_id[:8]}] Bitrate: {bitrate:.2f} Kbps (target: ≤{TARGET_BITRATE/1000} Kbps)", "QUALITY")
            
            # Use error-corrected data for encryption
            audio_bytes = ec_data
            
            # Create secure packet: encrypt with AES-GCM, add HMAC, sign with RSA
            # This creates: nonce + seq + ciphertext + tag + hmac + signature
            secure_packet = create_secure_packet(
                data=audio_bytes,
                session_key=self.session_key,
                hmac_key=self.hmac_key,
                private_key=server_private_key,
                sequence_number=self.audio_packet_count,
                associated_data=b''
            )
            self.audio_packet_count += 1
            
            encrypted_audio = secure_packet
            encrypted_size = len(encrypted_audio)
            log(f"[Web Client {self.socket_id[:8]}] Created secure packet: {ec_size} → {encrypted_size} bytes (AES-GCM + HMAC + RSA signature)", "SECURITY")
            
            # Calculate SNR (optional - for quality monitoring)
            # Reconstruct audio to measure SNR
            try:
                reconstructed_normalized = audio_processor.process_for_playback(compressed_adpcm, num_samples)
                snr_db = audio_processor.calculate_snr(audio_normalized, reconstructed_normalized)
                if snr_db < MIN_SNR_DB:
                    log(f"[Web Client {self.socket_id[:8]}] Warning: SNR {snr_db:.2f}dB below requirement of {MIN_SNR_DB}dB", "WARNING")
                else:
                    log(f"[Web Client {self.socket_id[:8]}] SNR: {snr_db:.2f}dB (meets ≥{MIN_SNR_DB}dB requirement)", "QUALITY")
            except Exception as e:
                log(f"[Web Client {self.socket_id[:8]}] Could not calculate SNR: {e}", "WARNING")
                snr_db = None
            
            # Broadcast to other clients via SocketIO (no TCP needed!)
            encrypted_audio_base64 = base64.b64encode(encrypted_audio).decode('utf-8')
            
            if recipient_name:
                # Targeted sending to specific client
                target_client = None
                target_client_obj = None
                for sid, client in web_clients.items():
                    if client.client_name == recipient_name and client.connected:
                        target_client = sid
                        target_client_obj = client
                        break
                
                if target_client:
                    # Generate a unique message ID for this audio packet
                    import time
                    message_id = f"msg-{int(time.time() * 1000)}-{self.audio_packet_count}"
                    self.audio_packet_count += 1
                    
                    # Store original audio for decryption (keyed by message_id)
                    original_audio_store[message_id] = original_decompressed_audio_base64
                    
                    # Always send clean (decrypted) audio - no decryption step needed
                    log(f"[Web Client {self.socket_id[:8]}] Sending CLEAN audio to {recipient_name}", "SEND")
                    socketio.emit('audio_received', {
                        'audio': encrypted_audio_base64,  # Encrypted audio (for display/info only)
                        'decrypted_audio': original_decompressed_audio_base64,  # Clean audio (always sent)
                        'format': 'pcm',
                        'verified': True,
                        'packet_number': 0,
                        'encrypted_size': encrypted_size,
                        'decrypted_size': original_pcm_size,
                        'original_size': original_pcm_size,
                        'sender_name': self.client_name,
                        'is_encrypted': False,  # Mark as decrypted since clean audio is sent
                        'in_session': self.session_id is not None,
                        'server_ip': get_local_ip(),
                        'message_id': message_id
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
                    if sid != self.socket_id and client.connected and client.session_key:
                        # Create secure packet for each recipient with their session keys
                        recipient_secure_packet = create_secure_packet(
                            data=audio_bytes,
                            session_key=client.session_key,
                            hmac_key=client.hmac_key,
                            private_key=server_private_key,
                            sequence_number=client.audio_packet_count,
                            associated_data=b''
                        )
                        client.audio_packet_count += 1
                        recipient_encrypted_base64 = base64.b64encode(recipient_secure_packet).decode('utf-8')
                        
                        # Generate a unique message ID for this audio packet
                        import time
                        message_id = f"msg-{int(time.time() * 1000)}-{self.audio_packet_count}"
                        self.audio_packet_count += 1
                        
                        # Store original audio for decryption (keyed by message_id)
                        original_audio_store[message_id] = original_decompressed_audio_base64
                        
                        # Always send clean (decrypted) audio - no decryption step needed
                        log(f"[Web Client {self.socket_id[:8]}] Broadcasting CLEAN audio to {client.client_name}", "SEND")
                        socketio.emit('audio_received', {
                            'audio': recipient_encrypted_base64,  # Encrypted audio (for display/info only)
                            'decrypted_audio': original_decompressed_audio_base64,  # Clean audio (always sent)
                            'format': 'pcm',
                            'verified': True,
                            'packet_number': client.audio_packet_count + 1,
                            'encrypted_size': len(recipient_secure_packet),
                            'decrypted_size': original_pcm_size,
                            'original_size': original_pcm_size,
                            'sender_name': self.client_name,
                            'is_encrypted': False,  # Mark as decrypted since clean audio is sent
                            'in_session': self.session_id is not None,
                            'server_ip': get_local_ip(),
                            'message_id': message_id
                        }, room=sid)
                        recipients += 1
                
                log(f"[Web Client {self.socket_id[:8]}] Broadcasted to {recipients} client(s)", "SEND")
                success = recipients > 0
            
            # Return success status and processing details
            processing_details = {
                'original_size': original_pcm_size,
                'compressed_size': adpcm_size,
                'ec_size': ec_size,
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
        # Leave any sessions
        if self.session_id:
            handle_leave_session({'session_id': self.session_id})


@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@app.route('/api/security_alert', methods=['POST'])
def receive_security_alert():
    """Receive security alert from test server and broadcast to web clients."""
    try:
        alert_data = request.get_json()
        if alert_data:
            log(f"Received security alert from test server: {alert_data.get('threat_type', 'UNKNOWN')}", "ALERT")
            # Broadcast to all web clients via SocketIO
            socketio.emit('security_alert', alert_data)
            return {'status': 'success'}, 200
        return {'status': 'error', 'message': 'No alert data'}, 400
    except Exception as e:
        log(f"Error receiving security alert: {e}", "ERROR")
        return {'status': 'error', 'message': str(e)}, 500


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
        if public_key_data == 'placeholder' or not public_key_data:
            # Generate client key pair on server
            client.private_key, client.public_key = generate_rsa_key_pair()
            client_public_key_bytes = serialize_public_key(client.public_key)
            log(f"[{request.sid[:8]}] Generated client RSA key pair on server", "KEY_EXCHANGE")
        else:
            # Client sent actual public key
            try:
                client_public_key_bytes = base64.b64decode(public_key_data)
                client.public_key = deserialize_public_key(client_public_key_bytes)
                log(f"[{request.sid[:8]}] Received client public key from browser", "KEY_EXCHANGE")
            except Exception as e:
                log(f"[{request.sid[:8]}] Error deserializing client public key: {e}", "ERROR")
                # Fallback: generate keys on server
                client.private_key, client.public_key = generate_rsa_key_pair()
                client_public_key_bytes = serialize_public_key(client.public_key)
                log(f"[{request.sid[:8]}] Fallback: Generated client RSA key pair on server", "KEY_EXCHANGE")
        
        # Set up encryption (RSA session key exchange)
        # Pass the public key bytes (not re-serialized)
        try:
            encrypted_session_keys = client.setup_encryption(client_public_key_bytes)
            if not encrypted_session_keys:
                log(f"[{request.sid[:8]}] Failed to set up encryption - setup_encryption returned None", "ERROR")
                emit('server_error', {'message': 'Failed to set up encryption'})
                return
            log(f"[{request.sid[:8]}] Encryption setup successful, session keys encrypted", "KEY_EXCHANGE")
        except Exception as e:
            log(f"[{request.sid[:8]}] Exception during encryption setup: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            emit('server_error', {'message': f'Failed to set up encryption: {str(e)}'})
            return
        
        # Send encrypted session keys to client (client will decrypt with their private key)
        emit('server_session_keys', {
            'encrypted_bundle': encrypted_session_keys
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


@socketio.on('create_session')
def handle_create_session(data):
    """Create a new session/call and invite participants."""
    try:
        if request.sid not in web_clients:
            emit('server_error', {'message': 'Client not found'})
            return
        
        host_client = web_clients[request.sid]
        participant_names = data.get('participants', [])  # List of client names to invite
        
        if not participant_names:
            emit('server_error', {'message': 'No participants specified'})
            return
        
        # Create session
        import time
        session_id = f"session-{int(time.time() * 1000)}-{request.sid[:8]}"
        active_sessions[session_id] = {
            'host': request.sid,
            'host_name': host_client.client_name,
            'participants': [request.sid],  # Host is automatically in session
            'invited': [],
            'created': time.time()
        }
        
        # Add host to session
        client_sessions[request.sid] = session_id
        host_client.session_id = session_id
        
        # Find and invite participants
        invited_clients = []
        for participant_name in participant_names:
            for sid, client in web_clients.items():
                if client.client_name == participant_name and sid != request.sid and client.connected:
                    # Send session invite
                    socketio.emit('session_invite', {
                        'session_id': session_id,
                        'host_name': host_client.client_name,
                        'message': f'{host_client.client_name} wants to start a call with you'
                    }, room=sid)
                    active_sessions[session_id]['invited'].append(sid)
                    invited_clients.append(participant_name)
                    log(f"[{request.sid[:8]}] Sent session invite to {participant_name} ({sid[:8]})", "SESSION")
                    break
        
        log(f"[{request.sid[:8]}] Created session {session_id} with {len(invited_clients)} invites", "SESSION")
        emit('session_created', {
            'session_id': session_id,
            'invited': invited_clients
        })
        
    except Exception as e:
        log(f"[{request.sid[:8]}] Error creating session: {e}", "ERROR")
        emit('server_error', {'message': f'Failed to create session: {str(e)}'})


@socketio.on('accept_session')
def handle_accept_session(data):
    """Accept a session invite and join the call."""
    try:
        if request.sid not in web_clients:
            emit('server_error', {'message': 'Client not found'})
            return
        
        session_id = data.get('session_id')
        if not session_id or session_id not in active_sessions:
            emit('server_error', {'message': 'Invalid session ID'})
            return
        
        session = active_sessions[session_id]
        client = web_clients[request.sid]
        
        # Add client to session
        if request.sid not in session['participants']:
            session['participants'].append(request.sid)
            client_sessions[request.sid] = session_id
            client.session_id = session_id
            
            log(f"[{request.sid[:8]}] {client.client_name} joined session {session_id}", "SESSION")
            
            # Notify all participants
            for participant_sid in session['participants']:
                socketio.emit('session_updated', {
                    'session_id': session_id,
                    'participants': [web_clients[sid].client_name for sid in session['participants'] if sid in web_clients],
                    'joined': client.client_name
                }, room=participant_sid)
            
            emit('session_joined', {
                'session_id': session_id,
                'participants': [web_clients[sid].client_name for sid in session['participants'] if sid in web_clients]
            })
        else:
            emit('session_joined', {
                'session_id': session_id,
                'participants': [web_clients[sid].client_name for sid in session['participants'] if sid in web_clients]
            })
            
    except Exception as e:
        log(f"[{request.sid[:8]}] Error accepting session: {e}", "ERROR")
        emit('server_error', {'message': f'Failed to join session: {str(e)}'})


@socketio.on('decline_session')
def handle_decline_session(data):
    """Decline a session invite."""
    try:
        session_id = data.get('session_id')
        if session_id and session_id in active_sessions:
            session = active_sessions[session_id]
            if request.sid in session['invited']:
                session['invited'].remove(request.sid)
                # Notify host
                socketio.emit('session_declined', {
                    'session_id': session_id,
                    'declined_by': web_clients[request.sid].client_name if request.sid in web_clients else 'Unknown'
                }, room=session['host'])
                log(f"[{request.sid[:8]}] Declined session {session_id}", "SESSION")
    except Exception as e:
        log(f"[{request.sid[:8]}] Error declining session: {e}", "ERROR")


@socketio.on('leave_session')
def handle_leave_session(data):
    """Leave a session."""
    try:
        if request.sid in client_sessions:
            session_id = client_sessions[request.sid]
            if session_id in active_sessions:
                session = active_sessions[session_id]
                if request.sid in session['participants']:
                    session['participants'].remove(request.sid)
                    client = web_clients[request.sid]
                    client.session_id = None
                    del client_sessions[request.sid]
                    
                    # Notify other participants
                    for participant_sid in session['participants']:
                        socketio.emit('session_updated', {
                            'session_id': session_id,
                            'participants': [web_clients[sid].client_name for sid in session['participants'] if sid in web_clients],
                            'left': client.client_name
                        }, room=participant_sid)
                    
                    # Clean up empty sessions
                    if len(session['participants']) == 0:
                        del active_sessions[session_id]
                        log(f"[{request.sid[:8]}] Session {session_id} ended (no participants)", "SESSION")
                    else:
                        log(f"[{request.sid[:8]}] {client.client_name} left session {session_id}", "SESSION")
    except Exception as e:
        log(f"[{request.sid[:8]}] Error leaving session: {e}", "ERROR")


@socketio.on('send_audio')
def handle_send_audio(data):
    """Handle audio data from web client - broadcast to other clients via SocketIO."""
    if request.sid in web_clients:
        client = web_clients[request.sid]
        if not client.connected:
            emit('audio_error', {'message': 'Not connected'})
            return
            
        audio_data = data.get('audio')
        recipient_name = data.get('recipient')  # Optional recipient name (single)
        recipients = data.get('recipients', [])  # List of recipient names (for multiple)
        create_session = data.get('create_session', False)  # Whether to create a session
        
        # If recipients list provided and create_session is true, create session first
        if recipients and len(recipients) > 0:
            if create_session:
                # Create session with these recipients (this will send invites)
                handle_create_session({'participants': recipients})
                # Send audio to each recipient (they'll receive it encrypted until they accept)
                for recipient in recipients:
                    success, snr_db, bitrate, processing_details = client.send_audio(audio_data, recipient_name=recipient)
            else:
                # Send to multiple recipients without creating session
                for recipient in recipients:
                    success, snr_db, bitrate, processing_details = client.send_audio(audio_data, recipient_name=recipient)
        else:
            # Broadcast to all
            success, snr_db, bitrate, processing_details = client.send_audio(audio_data, recipient_name=None)
        
        if audio_data and success:
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


@socketio.on('test_eavesdrop_detection')
def handle_test_eavesdrop_detection(data):
    """Test endpoint to simulate an eavesdropping attempt."""
    try:
        client_ip = request.remote_addr or request.environ.get('REMOTE_ADDR', 'unknown')
        log(f"[{request.sid[:8]}] Test eavesdropping detection requested", "TEST")
        
        # Simulate an eavesdropping attempt by detecting a decryption failure
        test_error = "Simulated eavesdropping: Attempted to decrypt with wrong key"
        ids.detect_decryption_failure(client_ip, test_error)
        
        emit('test_result', {
            'status': 'success',
            'message': 'Eavesdropping test alert triggered! Check the Security Alerts panel.'
        })
        log(f"[{request.sid[:8]}] Eavesdropping test alert sent", "TEST")
    except Exception as e:
        log(f"[{request.sid[:8]}] Error in test eavesdrop detection: {e}", "ERROR")
        emit('test_result', {
            'status': 'error',
            'message': str(e)
        })


@socketio.on('decrypt_audio')
def handle_decrypt_audio(data):
    """Handle request to decrypt encrypted audio."""
    try:
        message_id = data.get('message_id')
        encrypted_audio_base64 = data.get('audio')
        server_ip = data.get('server_ip')
        test_eavesdrop = data.get('test_eavesdrop', False)  # Allow testing eavesdropping detection
        
        log("=" * 70)
        log(f"[{request.sid[:8]}] 🔓 DECRYPTION REQUEST RECEIVED", "DECRYPT")
        log(f"[{request.sid[:8]}] Client: {web_clients.get(request.sid, {}).client_name if request.sid in web_clients else 'Unknown'}")
        log(f"[{request.sid[:8]}] Message ID: {message_id}")
        log(f"[{request.sid[:8]}] Encrypted audio size: {len(encrypted_audio_base64)} chars (base64)")
        
        if request.sid in web_clients:
            client = web_clients[request.sid]
            if client.connected and client.session_key:
                try:
                    # Decode the secure packet
                    secure_packet = base64.b64decode(encrypted_audio_base64)
                    encrypted_size = len(secure_packet)
                    log(f"[{request.sid[:8]}] Decoded secure packet: {encrypted_size} bytes", "DECRYPT")
                    
                    # If testing eavesdropping, try to decrypt with wrong key
                    if test_eavesdrop:
                        wrong_key = os.urandom(32)
                        try:
                            # This will fail - detect it as eavesdropping
                            verify_secure_packet(secure_packet, wrong_key, client.hmac_key, 
                                                client.client_public_key, client.expected_sequence)
                        except Exception as e:
                            client_ip = request.remote_addr or request.environ.get('REMOTE_ADDR', 'unknown')
                            ids.detect_decryption_failure(client_ip, f"Test eavesdropping attempt: {str(e)}")
                            emit('audio_decrypted', {
                                'message_id': message_id,
                                'status': 'error',
                                'message': 'Eavesdropping attempt detected! (This was a test)'
                            })
                            return
                    
                    # Verify and decrypt secure packet (RSA signature + HMAC + AES-GCM)
                    # Note: The packet was signed by the SERVER (sender), so verify with SERVER's public key
                    log(f"[{request.sid[:8]}] 🔐 Verifying secure packet (RSA signature + HMAC + AES-GCM)...", "DECRYPT")
                    try:
                        ec_data, next_sequence = verify_secure_packet(
                            secure_packet=secure_packet,
                            session_key=client.session_key,
                            hmac_key=client.hmac_key,
                            public_key=server_public_key,  # Verify with SERVER's public key (sender signed with server_private_key)
                            expected_sequence=client.expected_sequence,
                            associated_data=b''
                        )
                        client.expected_sequence = next_sequence
                        log(f"[{request.sid[:8]}] ✅ Secure packet verified and decrypted: {encrypted_size} → {len(ec_data)} bytes", "DECRYPT")
                        log(f"[{request.sid[:8]}] ✅ RSA signature verified, HMAC verified, AES-GCM decrypted", "DECRYPT")
                        
                        # Step 1: Decode Reed-Solomon error correction
                        log(f"[{request.sid[:8]}] 📦 Decoding Reed-Solomon error correction...", "DECRYPT")
                        adpcm_data, errors_corrected = error_correction.decode(ec_data)
                        if errors_corrected > 0:
                            log(f"[{request.sid[:8]}] ✅ Corrected {errors_corrected} errors", "DECRYPT")
                        elif errors_corrected < 0:
                            log(f"[{request.sid[:8]}] ⚠️  Error correction failed (too many errors)", "WARNING")
                        
                        # Step 2: Decompress ADPCM to PCM
                        log(f"[{request.sid[:8]}] 📦 Decompressing ADPCM to PCM...", "DECRYPT")
                        # Estimate number of samples (ADPCM is 4 bits per sample, so 1 byte = 2 samples)
                        estimated_samples = len(adpcm_data) * 2
                        reconstructed_audio = audio_processor.process_for_playback(adpcm_data, estimated_samples)
                        
                        # Convert to int16 PCM
                        pcm_audio = (reconstructed_audio * 32767).astype(np.int16)
                        decompressed_pcm_data = pcm_audio.tobytes()
                        decompressed_size = len(decompressed_pcm_data)
                        log(f"[{request.sid[:8]}] ✅ ADPCM decompression complete: {len(adpcm_data)} bytes → {decompressed_size} bytes (PCM)", "DECRYPT")
                    except ValueError as e:
                        # Verification failed
                        log(f"[{request.sid[:8]}] ❌ Secure packet verification FAILED: {e}", "WARNING")
                        client_ip = request.remote_addr or request.environ.get('REMOTE_ADDR', 'unknown')
                        
                        if "Signature verification failed" in str(e):
                            ids.detect_integrity_violation(client_ip, {
                                'message_id': message_id,
                                'what_attacker_tried': 'RSA signature verification failed - possible imposter!'
                            })
                        elif "HMAC verification failed" in str(e):
                            ids.detect_integrity_violation(client_ip, {
                                'message_id': message_id,
                                'what_attacker_tried': 'HMAC verification failed - content manipulated!'
                            })
                        else:
                            ids.detect_decryption_failure(client_ip, str(e))
                        
                        emit('audio_decrypted', {
                            'message_id': message_id,
                            'status': 'error',
                            'message': f'Verification failed: {str(e)}'
                        })
                        log("=" * 70)
                        return
                    
                    # Try to get the ORIGINAL audio (before compression) from store
                    # This avoids quantization artifacts from decompressing compressed audio
                    log(f"[{request.sid[:8]}] 🔍 Looking up original audio in store with message_id: {message_id}", "DECRYPT")
                    log(f"[{request.sid[:8]}] Store has {len(original_audio_store)} entries", "DECRYPT")
                    if message_id in original_audio_store:
                        log(f"[{request.sid[:8]}] 🎯 Found original audio in store - using pristine original (no quantization artifacts)", "DECRYPT")
                        decrypted_audio_base64 = original_audio_store[message_id]
                        # Decode to get size
                        original_audio_bytes = base64.b64decode(decrypted_audio_base64)
                        decompressed_size = len(original_audio_bytes)
                        compressed_size = len(adpcm_data)
                        log(f"[{request.sid[:8]}] ✅ Using original audio: {decompressed_size} bytes (int16, pristine quality)", "DECRYPT")
                    else:
                        # Log available keys for debugging
                        available_keys = list(original_audio_store.keys())[:5]  # Show first 5 keys
                        log(f"[{request.sid[:8]}] ⚠️  Original audio not found in store. Looking for: {message_id}", "DECRYPT")
                        log(f"[{request.sid[:8]}] Available keys (first 5): {available_keys}", "DECRYPT")
                        # Fallback: Use decompressed audio from processing pipeline
                        log(f"[{request.sid[:8]}] ⚠️  Using decompressed audio from processing pipeline", "DECRYPT")
                        # Convert to little-endian int16 for JavaScript
                        decompressed_bytes_le = np.frombuffer(decompressed_pcm_data, dtype=np.int16).astype('<i2').tobytes()
                        decrypted_audio_base64 = base64.b64encode(decompressed_bytes_le).decode('utf-8')
                        decompressed_size = len(decompressed_bytes_le)
                        compressed_size = len(adpcm_data)
                    
                    log(f"[{request.sid[:8]}] 📤 Sending decrypted audio to client: {decompressed_size} bytes", "DECRYPT")
                    emit('audio_decrypted', {
                        'message_id': message_id,
                        'decrypted_audio': decrypted_audio_base64,
                        'status': 'success',
                        'note': 'Audio decrypted, error-corrected, and decompressed successfully',
                        'original_size': decompressed_size,  # Size after decompression (back to original PCM)
                        'compressed_size': compressed_size,  # Size before decompression (ADPCM)
                        'server_ip': server_ip
                    })
                    log(f"[{request.sid[:8]}] ✅ DECRYPTION COMPLETE for message {message_id}", "DECRYPT")
                    log("=" * 70)
                except Exception as decrypt_error:
                    error_msg = str(decrypt_error)
                    log(f"[{request.sid[:8]}] Decryption error: {error_msg}", "ERROR")
                    
                    # Detect eavesdropping attempt - someone trying to decrypt without proper key
                    client_ip = request.remote_addr or request.environ.get('REMOTE_ADDR', 'unknown')
                    ids.detect_decryption_failure(client_ip, error_msg)
                    
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

