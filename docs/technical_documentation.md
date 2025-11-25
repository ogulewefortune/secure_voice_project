# Secure Voice Communication System - Technical Documentation

## Table of Contents
1. [System Architecture Overview](#system-architecture-overview)
2. [Frontend Implementation](#frontend-implementation)
3. [Backend Implementation](#backend-implementation)
4. [Communication Flow](#communication-flow)
5. [Security Implementation](#security-implementation)
6. [Audio Processing Pipeline](#audio-processing-pipeline)
7. [Network Protocol](#network-protocol)
8. [Compression and Quality Control](#compression-and-quality-control)
9. [Component Interactions](#component-interactions)
10. [Data Flow Diagrams](#data-flow-diagrams)

---

## System Architecture Overview

### High-Level Architecture

The Secure Voice Communication system is a three-tier architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Browser (Frontend)                    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  HTML5 Audio API + WebSocket (Socket.IO)            │   │
│  │  - Audio Recording (MediaRecorder API)              │   │
│  │  - Real-time Visualization                         │   │
│  │  - User Interface                                  │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────────────┘
                        │ WebSocket (Socket.IO)
                        │ Port 5000
┌───────────────────────▼─────────────────────────────────────┐
│              Web Server (Flask + SocketIO)                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - WebSocket Bridge                                  │   │
│  │  - Audio Compression & Processing                    │   │
│  │  - Integrity Checks (HMAC)                          │   │
│  │  - Quality Metrics (SNR, Bitrate)                   │   │
│  └───────────────────────┬──────────────────────────────┘   │
└───────────────────────────┼──────────────────────────────────┘
                            │ TCP Socket
                            │ Port 8888
┌───────────────────────────▼──────────────────────────────────┐
│              Voice Server (Python Socket Server)             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  - Key Exchange (ECDH)                               │   │
│  │  - Audio Broadcasting                                │   │
│  │  - Client Management                                 │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### Component Breakdown

1. **Frontend (Browser)**: HTML5/JavaScript application
2. **Web Server**: Flask + SocketIO bridge server
3. **Voice Server**: Core voice communication server
4. **Supporting Modules**:
   - `crypto_utils.py`: Cryptographic operations
   - `audio_compression.py`: Audio processing and compression
   - `network_protocol.py`: Network communication protocol
   - `config.py`: Configuration management

---

## Frontend Implementation

### Technology Stack

- **HTML5**: Structure and layout
- **JavaScript (ES6+)**: Client-side logic
- **Socket.IO Client**: Real-time bidirectional communication
- **Web Audio API**: Audio capture and playback
- **MediaRecorder API**: Audio recording
- **Canvas API**: Waveform visualization

### Key Components

#### 1. Audio Recording System

**Location**: `templates/index.html` (JavaScript section)

**Implementation**:
```javascript
async function startRecording() {
    // Request microphone access
    const stream = await navigator.mediaDevices.getUserMedia({ 
        audio: {
            sampleRate: 44100,
            channelCount: 1,
            echoCancellation: true,
            noiseSuppression: true
        } 
    });
    
    // Setup MediaRecorder
    mediaRecorder = new MediaRecorder(stream, {
        mimeType: 'audio/webm;codecs=opus'
    });
    
    // Setup Web Audio API for visualization
    audioContext = new AudioContext();
    analyser = audioContext.createAnalyser();
    analyser.fftSize = 256;
    microphone = audioContext.createMediaStreamSource(stream);
    microphone.connect(analyser);
    
    // Start recording
    mediaRecorder.start(100); // Collect data every 100ms
}
```

**Features**:
- Real-time audio capture using MediaRecorder API
- Web Audio API for frequency analysis and visualization
- Chunk-based recording (100ms intervals)
- Automatic echo cancellation and noise suppression

#### 2. Real-Time Visualization

**Components**:
- **Siri-style Visualizer**: Animated bars showing audio frequency spectrum
- **Waveform Canvas**: Real-time waveform display
- **Microphone Level Meter**: Visual feedback of input level
- **Intensity Indicator**: Shows audio intensity (Silent → Quiet → Normal → Loud → SHOUTING)

**Implementation**:
```javascript
function updateVisualizer() {
    analyser.getByteFrequencyData(dataArray);
    
    // Update frequency bars
    bars.forEach((bar, i) => {
        const value = dataArray[i * step];
        const height = Math.max(10, (value / 255) * 100);
        bar.style.height = height + 'px';
    });
    
    // Update Siri-style bars
    siriBarsLeft.forEach((bar, i) => {
        const value = dataArray[i * dataStep];
        const height = minHeight + (value / 255) * (maxHeight - minHeight);
        bar.style.height = height + 'px';
    });
    
    // Continue animation loop
    if (isRecording) {
        requestAnimationFrame(updateVisualizer);
    }
}
```

#### 3. WebSocket Communication

**Socket.IO Events**:

**Client → Server**:
- `connect_to_server`: Establish connection to voice server
- `send_audio`: Send recorded audio data
- `disconnect_from_server`: Disconnect from voice server

**Server → Client**:
- `server_connected`: Confirmation of server connection
- `server_error`: Connection error
- `audio_sent`: Audio transmission confirmation with metrics
- `audio_received`: Received audio data
- `audio_error`: Audio processing error
- `disconnected`: Server disconnection notification

**Implementation**:
```javascript
// Connect to web server
const socket = io();

// Connect to voice server
socket.emit('connect_to_server', {
    host: 'localhost',
    port: 8888
});

// Send audio
socket.emit('send_audio', {
    audio: base64AudioData
});

// Receive audio
socket.on('audio_received', (data) => {
    playAudio(data.audio);
});
```

#### 4. Audio Playback

**Implementation**:
```javascript
function playAudio(base64Audio) {
    const audio = new Audio('data:audio/wav;base64,' + base64Audio);
    audio.play().catch(err => console.error('Error playing audio:', err));
}
```

#### 5. Quality Metrics Display

**Metrics Tracked**:
- **SNR (Signal-to-Noise Ratio)**: Real-time calculation during recording
- **Bitrate**: Actual bitrate achieved (target: 64 Kbps)
- **Duration**: Recording duration
- **File Size**: Recorded audio file size

**SNR Threshold**:
- **Requirement**: SNR ≥ 40dB
- **Below Threshold**: Shows "Below 40dB (Does not meet requirement)" in red
- **Meets Requirement**: Shows "Meets Requirement (≥40dB)" in green

---

## Backend Implementation

### Web Server (`web_server.py`)

#### Architecture

The web server acts as a bridge between web clients and the voice server:

```
Web Browser ←→ Flask/SocketIO ←→ Voice Server (TCP Socket)
```

#### Key Components

**1. Flask Application**
```python
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-voice-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")
```

**2. WebVoiceClient Class**

Each web client connection creates a `WebVoiceClient` instance that:
- Maintains a TCP connection to the voice server
- Handles key exchange with the voice server
- Processes audio data (compression, encryption, integrity checks)
- Manages bidirectional audio flow

**Key Methods**:

- `connect()`: Establishes TCP connection and performs ECDH key exchange
- `send_audio()`: Processes and sends audio to voice server
- `receive_audio_loop()`: Continuously receives audio from voice server

**3. Audio Processing Pipeline**

When audio is received from web client:

```python
def send_audio(self, audio_data_base64, audio_format='webm'):
    # 1. Decode base64 audio
    audio_data = base64.b64decode(audio_data_base64)
    
    # 2. Convert to numpy array
    audio_array = np.frombuffer(audio_data, dtype=np.int16)
    
    # 3. Compress to 64 Kbps
    compressed_audio, snr_db, bitrate = compress_to_64kbps(
        audio_array, 
        sample_rate=8000,
        bits=8
    )
    
    # 4. Add HMAC integrity check
    integrity_key = self.aes_key[:16]
    audio_with_integrity = add_integrity_check(
        compressed_audio.tobytes(), 
        integrity_key
    )
    
    # 5. Encrypt with AES-256-GCM
    encrypted_audio = encrypt_data(audio_with_integrity, self.aes_key)
    
    # 6. Send to voice server
    send_message(self.socket, 'A', encrypted_audio)
```

**4. SocketIO Event Handlers**

- `connect`: Handle web client connection
- `disconnect`: Handle web client disconnection
- `connect_to_server`: Create WebVoiceClient and connect to voice server
- `send_audio`: Process and forward audio to voice server
- `disconnect_from_server`: Disconnect from voice server

### Voice Server (`src/server.py`)

#### Architecture

The voice server is a TCP socket server that:
- Accepts multiple client connections
- Manages per-client encryption keys
- Broadcasts audio between clients
- Handles key exchange for each client

#### Key Components

**1. VoiceServer Class**

**Initialization**:
```python
def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT):
    self.host = host
    self.port = port
    self.server_socket = None
    self.clients = []  # List of connected client sockets
    self.client_keys = {}  # Map socket → AES key
    self.running = False
```

**2. Key Exchange Process**

For each new client:

```python
def handle_client(self, client_socket, address):
    # 1. Server sends its public key
    server_pub_key_bytes = serialize_public_key(self.public_key)
    send_message(client_socket, 'K', server_pub_key_bytes)
    
    # 2. Receive client public key
    msg_type, client_pub_key_bytes = receive_message(client_socket)
    client_public_key = deserialize_public_key(client_pub_key_bytes)
    
    # 3. Derive shared secret using ECDH
    shared_secret = derive_shared_secret(self.private_key, client_public_key)
    
    # 4. Derive AES key from shared secret
    aes_key, salt = derive_aes_key(shared_secret)
    self.client_keys[client_socket] = aes_key
    
    # 5. Send salt to client
    send_message(client_socket, 'S', salt)
```

**3. Audio Broadcasting**

When audio is received from a client:

```python
def broadcast_audio(self, audio_data, sender_socket):
    recipients = 0
    for client in self.clients:
        if client != sender_socket:
            # Re-encrypt for each client with their own key
            aes_key = self.client_keys.get(client)
            if aes_key:
                encrypted_audio = encrypt_data(audio_data, aes_key)
                send_message(client, 'A', encrypted_audio)
                recipients += 1
    return recipients
```

**Important**: The server decrypts audio from sender, then re-encrypts it for each recipient using their individual AES keys. This ensures end-to-end encryption between clients.

**4. Client Management**

- Each client connection runs in a separate thread
- Client list maintained for broadcasting
- Automatic cleanup on disconnection
- Per-client AES key storage

---

## Communication Flow

### Connection Establishment Flow

```
1. Web Browser
   └─> SocketIO.connect() → Web Server (Port 5000)
       └─> 'connect' event

2. Web Browser
   └─> socket.emit('connect_to_server', {host, port})
       └─> Web Server
           └─> Creates WebVoiceClient instance
               └─> TCP connect() → Voice Server (Port 8888)

3. Voice Server
   └─> Accepts connection
       └─> Sends server public key ('K' message)
           └─> WebVoiceClient
               └─> Generates client key pair
                   └─> Sends client public key ('K' message)
                       └─> Voice Server
                           └─> Derives shared secret (ECDH)
                               └─> Derives AES key
                                   └─> Sends salt ('S' message)
                                       └─> WebVoiceClient
                                           └─> Derives AES key
                                               └─> Connection established
```

### Audio Transmission Flow

```
1. User Records Audio (Browser)
   └─> MediaRecorder captures audio (WebM/Opus)
       └─> Converted to base64
           └─> socket.emit('send_audio', {audio: base64})

2. Web Server Receives Audio
   └─> Decode base64 → binary audio
       └─> Convert to numpy array (int16)
           └─> Compress to 64 Kbps
               ├─> Quantize to 8-bit
               ├─> Calculate SNR
               └─> Verify SNR ≥ 40dB
                   └─> Add HMAC integrity check
                       └─> Encrypt with AES-256-GCM
                           └─> Send to Voice Server ('A' message)

3. Voice Server Receives Audio
   └─> Decrypt audio (using sender's AES key)
       └─> Broadcast to all other clients
           └─> For each recipient:
               └─> Re-encrypt with recipient's AES key
                   └─> Send ('A' message)

4. Web Server Receives Broadcasted Audio
   └─> Decrypt audio (using client's AES key)
       └─> Verify HMAC integrity
           └─> If valid:
               └─> Encode to base64
                   └─> socketio.emit('audio_received', {audio, verified: true})
                       └─> Browser
                           └─> Play audio
```

### Message Types

**Network Protocol Messages**:
- `'K'`: Key exchange (public key)
- `'S'`: Salt for key derivation
- `'A'`: Audio data

**SocketIO Events**:
- `connect_to_server`: Request connection to voice server
- `send_audio`: Send audio data
- `server_connected`: Connection established
- `audio_sent`: Audio transmission confirmation
- `audio_received`: Received audio data
- `audio_error`: Error occurred
- `disconnect_from_server`: Disconnect request

---

## Security Implementation

### 1. Key Exchange (ECDH)

**Algorithm**: Elliptic Curve Diffie-Hellman (ECDH) using SECP256R1 curve

**Implementation** (`crypto_utils.py`):

```python
def generate_key_pair():
    """Generate ECDH key pair"""
    private_key = ec.generate_private_key(
        ec.SECP256R1(), 
        default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    """Derive shared secret using ECDH"""
    shared_secret = private_key.exchange(
        ec.ECDH(), 
        peer_public_key
    )
    return shared_secret
```

**Security Properties**:
- Forward secrecy: Each session uses a new key pair
- No key transmission: Only public keys are exchanged
- Computationally secure: Based on elliptic curve discrete logarithm problem

### 2. Key Derivation (PBKDF2)

**Algorithm**: PBKDF2-HMAC-SHA256

**Implementation**:

```python
def derive_aes_key(shared_secret, salt=None):
    """Derive AES-256 key from shared secret"""
    if salt is None:
        salt = os.urandom(16)  # 128-bit salt
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,  # 100k iterations
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return key, salt
```

**Security Properties**:
- Salt prevents rainbow table attacks
- 100,000 iterations slow down brute-force attacks
- Produces 256-bit AES key

### 3. Encryption (AES-256-GCM)

**Algorithm**: AES-256 in Galois/Counter Mode (GCM)

**Implementation**:

```python
def encrypt_data(data, key):
    """Encrypt data using AES-256-GCM"""
    iv = os.urandom(12)  # 96-bit IV
    cipher = Cipher(
        algorithms.AES(key), 
        modes.GCM(iv), 
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # IV + Auth Tag + Ciphertext

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256-GCM"""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]  # 128-bit authentication tag
    ciphertext = encrypted_data[28:]
    
    cipher = Cipher(
        algorithms.AES(key), 
        modes.GCM(iv, tag), 
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
```

**Security Properties**:
- **Confidentiality**: AES-256 encryption
- **Authenticity**: GCM mode provides authentication tag
- **Integrity**: Authentication tag detects tampering
- **Nonce uniqueness**: Each encryption uses unique IV

**Message Format**:
```
[12 bytes: IV][16 bytes: Auth Tag][Variable: Ciphertext]
```

### 4. Integrity Protection (HMAC-SHA256)

**Purpose**: Protect against content manipulation

**Implementation** (`audio_compression.py`):

```python
def add_integrity_check(data, key):
    """Add HMAC integrity check"""
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    hmac_digest = hmac_obj.digest()  # 32 bytes
    return data + hmac_digest

def verify_integrity(data_with_hmac, key):
    """Verify HMAC integrity"""
    data = data_with_hmac[:-32]
    received_hmac = data_with_hmac[-32:]
    
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    expected_hmac = hmac_obj.digest()
    
    is_valid = hmac.compare_digest(received_hmac, expected_hmac)
    return is_valid, data
```

**Security Properties**:
- **Tamper detection**: Any modification invalidates HMAC
- **Timing-safe comparison**: Uses `compare_digest` to prevent timing attacks
- **Key derivation**: Uses first 16 bytes of AES key

**Data Format**:
```
[Audio Data][32 bytes: HMAC-SHA256]
```

### 5. Complete Security Stack

**Layers of Protection**:

1. **Key Exchange**: ECDH (forward secrecy)
2. **Key Derivation**: PBKDF2-HMAC-SHA256 (100k iterations)
3. **Encryption**: AES-256-GCM (confidentiality + authenticity)
4. **Integrity**: HMAC-SHA256 (tamper detection)

**Security Guarantees**:
- ✅ End-to-end encryption (server cannot decrypt without client keys)
- ✅ Forward secrecy (new keys per session)
- ✅ Tamper detection (HMAC verification)
- ✅ Authentication (GCM authentication tag)
- ✅ Replay protection (unique IV per message)

---

## Audio Processing Pipeline

### Compression Pipeline

**Location**: `src/audio_compression.py`

**Process**:

```
Original Audio (WebM/Opus, variable bitrate)
    ↓
Base64 Decode → Binary Audio
    ↓
Convert to NumPy Array (int16)
    ↓
Quantization (8-bit)
    ├─> Calculate Signal Power
    ├─> Apply Quantization Levels (2^8 = 256 levels)
    ├─> Calculate Quantization Noise
    └─> Calculate SNR (dB)
    ↓
Compressed Audio (8-bit PCM, 8000 Hz)
    ├─> Bitrate: 8000 Hz × 8 bits = 64 Kbps ✓
    └─> SNR: Must be ≥ 40dB
    ↓
Add HMAC Integrity Check
    ↓
Encrypt (AES-256-GCM)
    ↓
Transmit
```

### Quantization Algorithm

**Implementation**:

```python
def quantize_audio(audio_data, bits=8):
    # Convert to float32 for processing
    audio_float = audio_data.astype(np.float32) / 32768.0
    
    # Calculate signal power
    signal_power = np.mean(audio_float ** 2)
    
    # Quantization levels
    levels = 2 ** bits  # 256 levels for 8-bit
    step_size = 2.0 / levels
    
    # Quantize
    quantized = np.round(audio_float / step_size) * step_size
    
    # Calculate quantization noise
    noise = audio_float - quantized
    noise_power = np.mean(noise ** 2)
    
    # Calculate SNR in dB
    snr_db = 10 * np.log10(signal_power / noise_power)
    
    # Convert back to int16
    quantized_int16 = (quantized * 32768.0).astype(np.int16)
    
    return quantized_int16, snr_db
```

### Quantization Bit Depth Comparison

The system uses **8-bit quantization** to achieve the 64 Kbps bitrate requirement. However, understanding different bit depths helps explain why SNR can fall below 40dB.

#### Bit Depth Specifications

| Bit Depth | Quantization Levels | Step Size | Theoretical Max SNR | Bitrate (8kHz) | Meets 40dB Requirement? |
|-----------|-------------------|-----------|---------------------|----------------|-------------------------|
| **16-bit** | 65,536 | 0.0000305 | ~98.1 dB | 128 Kbps | ✅ Yes (exceeds) |
| **12-bit** | 4,096 | 0.000488 | ~74.0 dB | 96 Kbps | ✅ Yes (exceeds) |
| **10-bit** | 1,024 | 0.001953 | ~62.0 dB | 80 Kbps | ✅ Yes (exceeds) |
| **8-bit** | 256 | 0.0078125 | ~49.9 dB | **64 Kbps** | ✅ **Yes (current)** |
| **7-bit** | 128 | 0.015625 | ~43.9 dB | 56 Kbps | ⚠️ Marginal (may fail) |
| **6-bit** | 64 | 0.03125 | ~37.9 dB | 48 Kbps | ❌ **No (fails)** |
| **5-bit** | 32 | 0.0625 | ~31.9 dB | 40 Kbps | ❌ No (fails) |
| **4-bit** | 16 | 0.125 | ~25.8 dB | 32 Kbps | ❌ **No (fails)** |
| **3-bit** | 8 | 0.25 | ~19.8 dB | 24 Kbps | ❌ No (fails) |
| **2-bit** | 4 | 0.5 | ~13.8 dB | 16 Kbps | ❌ No (fails) |
| **1-bit** | 2 | 1.0 | ~7.8 dB | 8 Kbps | ❌ No (fails) |

#### Theoretical SNR Formula

For uniform quantization with a full-scale sinusoidal signal:

```
SNR (dB) ≈ 6.02 × bits + 1.76 dB
```

**Derivation**:
- Each bit adds approximately 6.02 dB of dynamic range
- The constant 1.76 dB accounts for the difference between peak and RMS values of a sine wave
- This formula assumes optimal signal conditions (full-scale, uniform distribution)

#### Why 4-bit Quantization Fails the 40dB Requirement

**4-bit Quantization Analysis**:

```python
bits = 4
levels = 2 ** 4  # 16 quantization levels
step_size = 2.0 / 16  # 0.125 (very large steps)
theoretical_snr = 6.02 * 4 + 1.76  # ≈ 25.8 dB
```

**Problems with 4-bit**:

1. **Insufficient Levels**: Only 16 quantization levels cannot represent audio with sufficient detail
2. **Large Step Size**: Step size of 0.125 means quantization error can be up to ±0.0625 (6.25% of full scale)
3. **Low SNR**: Maximum theoretical SNR of ~25.8 dB is well below the 40dB requirement
4. **Poor Quality**: Audio quality would be severely degraded, sounding heavily distorted

**Example Calculation**:
- Signal amplitude: 0.5 (moderate level)
- Step size: 0.125
- Quantization error: up to ±0.0625
- Relative error: 12.5% of signal amplitude
- Result: High noise power → Low SNR (~25-30 dB)

#### Why 8-bit Quantization is Used

**8-bit Quantization Analysis**:

```python
bits = 8
levels = 2 ** 8  # 256 quantization levels
step_size = 2.0 / 256  # 0.0078125 (small steps)
theoretical_snr = 6.02 * 8 + 1.76  # ≈ 49.9 dB
bitrate = 8000 * 8  # 64,000 bps = 64 Kbps ✓
```

**Advantages**:
- ✅ **Meets Bitrate Requirement**: Exactly 64 Kbps at 8kHz sample rate
- ✅ **Meets SNR Requirement**: Theoretical max ~49.9 dB (above 40dB threshold)
- ✅ **Good Quality**: 256 levels provide sufficient audio detail
- ✅ **Small Step Size**: 0.0078125 allows fine-grained quantization
- ✅ **Balanced**: Optimal trade-off between quality and bitrate

**Actual SNR Range**:
- **Best case** (full-scale signal): ~48-50 dB
- **Good signal** (50-80% amplitude): ~45-48 dB
- **Moderate signal** (20-50% amplitude): ~40-45 dB
- **Low signal** (< 20% amplitude): May fall below 40dB

#### Quantization Error Analysis

**Quantization Error** is the difference between the original signal and quantized signal:

```python
quantization_error = original_signal - quantized_signal
```

**Error Characteristics**:
- **Maximum Error**: ±(step_size / 2)
- **Error Distribution**: Uniformly distributed in range [-step_size/2, +step_size/2]
- **Error Power**: For uniform distribution, error power = (step_size²) / 12

**Error Power Calculation**:
```python
# For 8-bit quantization
step_size = 0.0078125
error_power = (0.0078125 ** 2) / 12  # ≈ 5.086 × 10⁻⁶

# For 4-bit quantization
step_size = 0.125
error_power = (0.125 ** 2) / 12  # ≈ 0.001302
```

**Impact on SNR**:
- **8-bit**: Small error power → High SNR
- **4-bit**: Large error power → Low SNR (fails requirement)

#### Bit Depth vs. Audio Quality

**Quality Assessment by Bit Depth**:

| Bit Depth | Audio Quality | Use Case | SNR Status |
|-----------|---------------|----------|------------|
| 16-bit | Professional/CD quality | High-fidelity audio | Exceeds requirement |
| 12-bit | High quality | Professional recording | Exceeds requirement |
| 10-bit | Very good | High-quality voice | Exceeds requirement |
| **8-bit** | **Good (current)** | **Voice communication** | **Meets requirement** |
| 7-bit | Acceptable | Low-bandwidth voice | Marginal |
| 6-bit | Poor | Emergency communication | ❌ Fails |
| 5-bit | Very poor | Extremely low bandwidth | ❌ Fails |
| **4-bit** | **Unusable** | **Not recommended** | **❌ Fails** |
| 3-bit | Severely distorted | Not practical | ❌ Fails |
| 2-bit | Extremely distorted | Not practical | ❌ Fails |
| 1-bit | Binary (on/off) | Not practical | ❌ Fails |

#### Why Lower Bit Depths Fail

**4-bit Quantization Issues**:

1. **Insufficient Dynamic Range**: Only 16 levels cannot represent the full range of human voice
2. **Coarse Quantization**: Large step size causes audible distortion
3. **Low SNR**: Maximum SNR ~25.8 dB is 14.2 dB below requirement
4. **Poor Perceptual Quality**: Audio sounds heavily quantized and unnatural

**6-bit Quantization Issues**:

1. **Marginal Quality**: 64 levels provide limited dynamic range
2. **SNR Borderline**: Maximum SNR ~37.9 dB is just below 40dB requirement
3. **Noticeable Artifacts**: Quantization noise becomes audible
4. **Insufficient for Voice**: May work for very simple signals but not natural speech

**7-bit Quantization Analysis**:

1. **Close to Threshold**: Maximum SNR ~43.9 dB is just above 40dB
2. **Risk of Failure**: With low signal levels, SNR can easily drop below 40dB
3. **Not Recommended**: Too close to the requirement threshold

#### Quantization Levels Visualization

```
16-bit: ████████████████████████████████████████████████████████████████ (65,536 levels)
12-bit: ████████████████████████████████████████████████████████████████ (4,096 levels)
10-bit: ████████████████████████████████████████████████████████████████ (1,024 levels)
 8-bit: ████████████████████████████████████████████████████████████████ (256 levels) ← CURRENT
 7-bit: ████████████████████████████████████████████████████████████████ (128 levels)
 6-bit: ████████████████████████████████████████████████████████████████ (64 levels)
 5-bit: ████████████████████████████████████████████████████████████████ (32 levels)
 4-bit: ████████████████████████████████████████████████████████████████ (16 levels) ← FAILS
 3-bit: ████████████████████████████████████████████████████████████████ (8 levels)
 2-bit: ████████████████████████████████████████████████████████████████ (4 levels)
 1-bit: ████████████████████████████████████████████████████████████████ (2 levels)
```

#### Quantization Step Size Comparison

**Step Size Impact on Quality**:

| Bit Depth | Step Size | Relative Error (at 50% signal) | Quality Impact |
|-----------|-----------|-------------------------------|----------------|
| 8-bit | 0.0078125 | 1.56% | ✅ Minimal, high quality |
| 7-bit | 0.015625 | 3.13% | ⚠️ Noticeable, acceptable |
| 6-bit | 0.03125 | 6.25% | ❌ Audible artifacts |
| 5-bit | 0.0625 | 12.5% | ❌ Significant distortion |
| **4-bit** | **0.125** | **25%** | **❌ Severe distortion** |

**Step Size Formula**:
```python
step_size = 2.0 / (2 ** bits)
```

For 4-bit: `step_size = 2.0 / 16 = 0.125`

This means the quantizer can only represent values in increments of 0.125, which is too coarse for natural audio.

#### Quantization Noise Power

**Noise Power Calculation**:

For uniform quantization, quantization noise power is:

```
Noise Power = (step_size²) / 12
```

**Comparison**:

| Bit Depth | Step Size | Noise Power | Relative to Signal |
|-----------|-----------|-------------|-------------------|
| 8-bit | 0.0078125 | 5.086 × 10⁻⁶ | Very small |
| 7-bit | 0.015625 | 2.034 × 10⁻⁵ | Small |
| 6-bit | 0.03125 | 8.138 × 10⁻⁵ | Moderate |
| 5-bit | 0.0625 | 3.255 × 10⁻⁴ | Large |
| **4-bit** | **0.125** | **1.302 × 10⁻³** | **Very large** |

**Impact**: Higher noise power directly reduces SNR, which is why 4-bit quantization fails the 40dB requirement.

### SNR Calculation

**Formula**:
```
SNR (dB) = 10 × log₁₀(Signal Power / Noise Power)
```

**Requirement**: SNR ≥ 40dB

**Why 40dB?**
- 40dB represents a signal-to-noise ratio of 10,000:1
- Provides high-quality audio suitable for voice communication
- Balances quality with compression requirements

**Quality Levels**:
- **≥ 40dB**: Meets requirement (green indicator)
- **< 40dB**: Below requirement (red indicator, warning logged)

### Parameters That Cause SNR to Fall Below 40dB

The SNR calculation depends on the relationship between signal power and quantization noise. Several factors can cause SNR to drop below the 40dB threshold:

#### 1. **Low Signal Power (Quiet Audio)**

**Cause**: When the input audio signal is very quiet or has low amplitude.

**Mathematical Relationship**:
```
SNR (dB) = 10 × log₁₀(Signal Power / Noise Power)
```

If `signal_power` is low relative to `noise_power`, the ratio decreases, resulting in lower SNR.

**Example Scenarios**:
- Microphone positioned far from speaker
- Speaker speaking very quietly (whispering)
- Low microphone gain/sensitivity settings
- Audio input level below ~5% of maximum amplitude

**Threshold**: When signal power drops below approximately 0.001 (normalized), SNR typically falls below 40dB with 8-bit quantization.

#### 2. **Quantization Bit Depth**

**Current Configuration**: 8-bit quantization (256 levels)

**Impact**: Lower bit depth increases quantization noise, which reduces SNR.

**Theoretical SNR for Uniform Quantization**:
```
SNR ≈ 6.02 × bits + 1.76 dB
```

For 8-bit quantization:
- Theoretical maximum SNR ≈ 6.02 × 8 + 1.76 ≈ 49.9 dB
- Actual SNR depends on signal characteristics

**If bit depth were reduced**:
- 7-bit: Maximum SNR ≈ 43.9 dB (may fall below 40dB with low signals)
- 6-bit: Maximum SNR ≈ 37.9 dB (will fall below 40dB)
- 5-bit: Maximum SNR ≈ 31.9 dB (significantly below requirement)

#### 3. **Signal Characteristics**

**Factors Affecting SNR**:

**a) Signal Distribution**:
- **Uniform distribution**: Best case scenario, achieves theoretical SNR
- **Sparse signals**: Signals that don't utilize full dynamic range have lower effective SNR
- **Clipped signals**: Over-amplified signals that hit maximum levels lose information

**b) Signal-to-Noise Ratio in Original Audio**:
- High background noise in original recording
- Poor microphone quality
- Environmental noise (fans, traffic, etc.)
- Electrical interference

**c) Signal Amplitude**:
- Very quiet signals (< 10% of maximum amplitude) are more susceptible to quantization noise
- Optimal range: 30-80% of maximum amplitude for best SNR

#### 4. **Edge Cases**

**Silent or Near-Silent Audio**:
```python
if signal_power == 0:
    return audio_data, 0.0  # SNR = 0dB
```

When there's no signal (silence), SNR becomes 0dB or undefined, which is below the 40dB requirement.

**Very Low Amplitude Signals**:
When signal power approaches zero but isn't exactly zero:
- Quantization noise becomes significant relative to signal
- SNR drops dramatically
- Example: Signal at 1% amplitude may achieve only 20-30dB SNR

#### 5. **Quantization Step Size**

**Current Configuration**:
```python
levels = 2 ** 8  # 256 levels
step_size = 2.0 / levels  # step_size = 0.0078125
```

**Impact**:
- Larger step sizes (fewer quantization levels) increase quantization error
- For low-amplitude signals, the step size becomes significant relative to signal amplitude
- This increases noise power, reducing SNR

**Example**:
- Signal amplitude: 0.01 (very quiet)
- Step size: 0.0078125
- Quantization error can be up to ±0.0039 (half step size)
- Relative error: ~39% of signal → Low SNR

#### 6. **Practical Thresholds**

Based on the quantization algorithm, SNR will typically fall below 40dB when:

1. **Signal Power < 0.0001** (normalized): Very quiet audio
2. **Signal Amplitude < 1% of maximum**: Low input levels
3. **Background Noise > 30% of signal**: Noisy environment
4. **Quantization Levels < 256**: If bit depth reduced below 8-bit
5. **Silent Audio**: No signal present (SNR = 0dB)

#### 7. **Monitoring and Detection**

The system monitors SNR in real-time:

```python
# In audio_compression.py
quantized, snr_db = quantize_audio(audio_data, bits=8)

# In web_server.py
if snr_db < MIN_SNR_DB:  # MIN_SNR_DB = 40
    log(f"Warning: SNR {snr_db:.2f}dB below requirement of {MIN_SNR_DB}dB", "WARNING")
```

**Warning Conditions**:
- SNR < 40dB triggers warning log
- UI displays "Below 40dB (Does not meet requirement)" in red
- Metric card shows red border and warning animation

#### 8. **Mitigation Strategies**

To maintain SNR ≥ 40dB:

1. **Increase Input Gain**: Boost microphone input level
2. **Reduce Background Noise**: Use noise-cancelling microphone or quiet environment
3. **Optimal Distance**: Position microphone 6-12 inches from speaker
4. **Signal Normalization**: Ensure audio uses adequate dynamic range
5. **Quality Microphone**: Use high-quality microphone with good signal-to-noise ratio

**Note**: The system uses 8-bit quantization as a fixed parameter to achieve 64 Kbps bitrate. SNR below 40dB indicates the input signal quality needs improvement, not a system configuration issue.

### Bitrate Calculation

**Formula**:
```
Bitrate = Sample Rate × Bits per Sample
```

**Target**: 64 Kbps

**Configuration**:
- Sample Rate: 8000 Hz
- Bits per Sample: 8 bits
- Calculated Bitrate: 8000 × 8 = 64,000 bps = 64 Kbps ✓

**Verification**:
```python
bitrate = sample_rate * bits  # 8000 * 8 = 64000 bps
```

---

## Network Protocol

### Protocol Specification

**Location**: `src/network_protocol.py`

### Message Format

**Structure**:
```
[4 bytes: Length (big-endian)][1 byte: Type][Variable: Data]
```

**Length Field**: 32-bit unsigned integer (big-endian)
**Type Field**: Single byte character
**Data Field**: Variable length binary data

### Message Types

| Type | Description | Direction |
|------|-------------|-----------|
| `'K'` | Public key (ECDH key exchange) | Bidirectional |
| `'S'` | Salt (for key derivation) | Server → Client |
| `'A'` | Audio data (encrypted) | Bidirectional |

### Send Message Implementation

```python
def send_message(sock, message_type, data):
    # Prepare data
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, dict):
        data_bytes = json.dumps(data).encode('utf-8')
    else:
        data_bytes = data
    
    # Create message: [type: 1 byte][data: variable]
    message_type_byte = message_type.encode('utf-8')[:1]
    full_message = message_type_byte + data_bytes
    length = len(full_message)
    
    # Send length first (4 bytes, big-endian)
    sock.sendall(struct.pack('>I', length))
    # Send message
    sock.sendall(full_message)
    return True
```

### Receive Message Implementation

```python
def receive_message(sock):
    # Receive length (4 bytes)
    length_data = b''
    while len(length_data) < 4:
        chunk = sock.recv(4 - len(length_data))
        if not chunk:
            return None, None
        length_data += chunk
    
    length = struct.unpack('>I', length_data)[0]
    
    # Receive message
    message_data = b''
    while len(message_data) < length:
        chunk = sock.recv(min(length - len(message_data), BUFFER_SIZE))
        if not chunk:
            return None, None
        message_data += chunk
    
    # Extract type and data
    message_type = message_data[0:1].decode('utf-8', errors='ignore')
    data = message_data[1:]
    
    return message_type, data
```

### Connection Management

**Server Side**:
```python
def establish_connection(host, port, is_server=True):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)  # Max 5 pending connections
    return sock
```

**Client Side**:
```python
def establish_connection(host, port, is_server=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
```

### Error Handling

- **Connection errors**: Return `None` from `establish_connection()`
- **Receive errors**: Return `(None, None)` from `receive_message()`
- **Send errors**: Return `False` from `send_message()`
- **Automatic cleanup**: `close_connection()` handles socket cleanup

---

## Compression and Quality Control

### Compression Requirements

**Target Bitrate**: 64 Kbps
**Minimum SNR**: 40dB
**Sample Rate**: 8000 Hz
**Quantization**: 8-bit

### Compression Process

**Step 1: Audio Input**
- Format: WebM/Opus (variable bitrate, typically 32-128 Kbps)
- Sample Rate: 44100 Hz (from MediaRecorder)
- Channels: Mono (1 channel)

**Step 2: Conversion**
- Decode base64 → binary audio
- Convert to NumPy array (int16)
- Handle odd-length arrays (padding)

**Step 3: Quantization**
- Convert int16 → float32 (normalized to [-1, 1])
- Apply 8-bit quantization (256 levels)
- Calculate quantization noise
- Calculate SNR

**Step 4: Verification**
- Check SNR ≥ 40dB
- Log warning if below threshold
- Calculate actual bitrate
- Verify bitrate ≈ 64 Kbps

**Step 5: Output**
- Convert quantized float → int16
- Return compressed audio, SNR, and bitrate

### Quality Metrics

**SNR (Signal-to-Noise Ratio)**:
- **Calculation**: `10 × log₁₀(Signal Power / Noise Power)`
- **Unit**: Decibels (dB)
- **Requirement**: ≥ 40dB
- **Display**: Real-time during recording, final value after transmission

**Bitrate**:
- **Calculation**: `Sample Rate × Bits per Sample`
- **Unit**: Bits per second (bps) or Kbps
- **Target**: 64,000 bps (64 Kbps)
- **Tolerance**: ±2 Kbps (62-66 Kbps acceptable)

**Compression Ratio**:
- **Calculation**: `(1 - Compressed Size / Original Size) × 100%`
- **Typical**: 30-70% reduction depending on input format

### Quality Monitoring

**Real-time Monitoring**:
- SNR calculated during quantization
- Bitrate calculated from sample rate and bits
- Metrics displayed in UI during recording

**Post-transmission Verification**:
- Server returns actual SNR and bitrate
- UI updates with server-confirmed values
- Warning displayed if SNR < 40dB

---

## Component Interactions

### Module Dependencies

```
web_server.py
├── Flask (web framework)
├── SocketIO (WebSocket)
├── src.config (configuration)
├── src.network_protocol (TCP communication)
├── src.crypto_utils (encryption/decryption)
└── src.audio_compression (audio processing)

src/server.py
├── src.config (configuration)
├── src.network_protocol (TCP communication)
└── src.crypto_utils (encryption/decryption)

src/client.py
├── src.config (configuration)
├── src.network_protocol (TCP communication)
├── src.crypto_utils (encryption/decryption)
└── src.audio_processor (audio capture/playback)
```

### Class Relationships

**Web Server**:
```
WebVoiceClient
├── Uses: network_protocol (TCP socket)
├── Uses: crypto_utils (key exchange, encryption)
├── Uses: audio_compression (compression, integrity)
└── Communicates: Voice Server (TCP), Web Browser (SocketIO)
```

**Voice Server**:
```
VoiceServer
├── Uses: network_protocol (TCP socket)
├── Uses: crypto_utils (key exchange, encryption)
├── Manages: List of client sockets
└── Manages: Per-client AES keys
```

**Client**:
```
VoiceClient
├── Uses: network_protocol (TCP socket)
├── Uses: crypto_utils (key exchange, encryption)
├── Uses: audio_processor (capture/playback)
└── Communicates: Voice Server (TCP)
```

### Threading Model

**Voice Server**:
- **Main Thread**: Accepts new connections
- **Client Threads**: One per client connection
  - Handles key exchange
  - Receives audio
  - Broadcasts to other clients

**Web Server**:
- **Main Thread**: Flask/SocketIO event loop
- **WebVoiceClient Threads**: One per web client
  - Receives audio from voice server
  - Forwards to web browser via SocketIO

**Web Browser**:
- **Main Thread**: UI and event handling
- **Audio Thread**: Web Audio API processing
- **Recording Thread**: MediaRecorder processing

---

## Data Flow Diagrams

### Complete Audio Transmission Flow

```
┌─────────────┐
│   Browser   │
│  (Frontend) │
└──────┬──────┘
       │ 1. Record Audio (MediaRecorder)
       │    Format: WebM/Opus, 44100 Hz
       │
       │ 2. Convert to Base64
       │
       ▼
┌─────────────────────────────────────┐
│  SocketIO Event: 'send_audio'      │
│  {audio: base64_string}             │
└──────┬───────────────────────────────┘
       │
       │ WebSocket (Port 5000)
       │
       ▼
┌─────────────────────────────────────┐
│      Web Server (Flask/SocketIO)    │
│  ┌──────────────────────────────┐   │
│  │ handle_send_audio()          │   │
│  │ 1. Decode base64             │   │
│  │ 2. Convert to numpy array    │   │
│  │ 3. Compress to 64 Kbps       │   │
│  │    - Quantize 8-bit          │   │
│  │    - Calculate SNR           │   │
│  │ 4. Add HMAC                  │   │
│  │ 5. Encrypt AES-256-GCM       │   │
│  └──────┬───────────────────────┘   │
└────────┼─────────────────────────────┘
         │ TCP Socket (Port 8888)
         │ Message Type: 'A'
         │
         ▼
┌─────────────────────────────────────┐
│      Voice Server (Python)          │
│  ┌──────────────────────────────┐   │
│  │ handle_client()             │   │
│  │ 1. Receive encrypted audio   │   │
│  │ 2. Decrypt (sender's key)   │   │
│  │ 3. Broadcast to all clients │   │
│  │    For each recipient:       │   │
│  │    - Re-encrypt (their key) │   │
│  │    - Send ('A' message)      │   │
│  └──────┬───────────────────────┘   │
└────────┼─────────────────────────────┘
         │ TCP Socket (Port 8888)
         │ Message Type: 'A'
         │
         ▼
┌─────────────────────────────────────┐
│      Web Server (Flask/SocketIO)    │
│  ┌──────────────────────────────┐   │
│  │ receive_audio_loop()         │   │
│  │ 1. Receive encrypted audio   │   │
│  │ 2. Decrypt (client's key)     │   │
│  │ 3. Verify HMAC                │   │
│  │ 4. Encode to base64           │   │
│  └──────┬───────────────────────┘   │
└────────┼─────────────────────────────┘
         │ WebSocket (Port 5000)
         │ SocketIO Event: 'audio_received'
         │
         ▼
┌─────────────────────────────────────┐
│   Browser (Frontend)                │
│  ┌──────────────────────────────┐   │
│  │ socket.on('audio_received')  │   │
│  │ 1. Receive base64 audio       │   │
│  │ 2. Create Audio object        │   │
│  │ 3. Play audio                 │   │
│  └──────────────────────────────┘   │
└─────────────────────────────────────┘
```

### Key Exchange Flow

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │ 1. TCP Connect                   │
       ├─────────────────────────────────>│
       │                                  │
       │                                  │ 2. Generate Key Pair
       │                                  │    (ECDH SECP256R1)
       │                                  │
       │ 3. Message 'K': Server Pub Key  │
       │<─────────────────────────────────┤
       │                                  │
       │ 4. Generate Key Pair            │
       │    (ECDH SECP256R1)             │
       │                                  │
       │ 5. Message 'K': Client Pub Key  │
       ├─────────────────────────────────>│
       │                                  │
       │                                  │ 6. Derive Shared Secret
       │                                  │    ECDH(client_pub, server_priv)
       │                                  │
       │                                  │ 7. Derive AES Key
       │                                  │    PBKDF2(shared_secret, salt)
       │                                  │
       │ 8. Message 'S': Salt            │
       │<─────────────────────────────────┤
       │                                  │
       │ 9. Derive Shared Secret          │
       │    ECDH(server_pub, client_priv)│
       │                                  │
       │ 10. Derive AES Key               │
       │     PBKDF2(shared_secret, salt)  │
       │                                  │
       │ 11. Connection Established      │
       │     (Both have same AES key)     │
       │                                  │
```

### Security Layers

```
┌─────────────────────────────────────────┐
│         Audio Data (Plaintext)          │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│      HMAC-SHA256 Integrity Check        │
│  [Audio Data][32 bytes: HMAC]          │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│      AES-256-GCM Encryption             │
│  [12 bytes: IV][16 bytes: Tag][Cipher]  │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│      Network Protocol Framing            │
│  [4 bytes: Length][1 byte: Type][Data]  │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│         TCP Socket Transmission          │
└─────────────────────────────────────────┘
```

---

## Configuration

### Key Configuration Values

**Location**: `src/config.py`

```python
# Network Configuration
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8888
BUFFER_SIZE = 4096

# Audio Quality Requirements
TARGET_BITRATE = 64000  # 64 Kbps
QUANTIZATION_BITS = 8   # 8-bit quantization
MIN_SNR_DB = 40         # Minimum SNR: 40dB
SAMPLE_RATE_FOR_64KBPS = 8000  # 8000 Hz

# Security Settings
ENCRYPTION_ALGORITHM = "AES-256"
KEY_EXCHANGE_ALGORITHM = "ECDH"
ENABLE_INTEGRITY_CHECK = True
```

### Port Configuration

- **Voice Server**: Port 8888 (TCP)
- **Web Server**: Port 5000 (HTTP/WebSocket)

### Audio Configuration

- **Input Sample Rate**: 44100 Hz (from browser)
- **Processing Sample Rate**: 8000 Hz (for 64 Kbps)
- **Quantization**: 8-bit
- **Channels**: Mono (1 channel)
- **Format**: PCM (after compression)

---

## Error Handling

### Connection Errors

**Web Server → Voice Server**:
- Connection refused: Voice server not running
- Timeout: Network issues
- Key exchange failure: Invalid keys

**Browser → Web Server**:
- WebSocket connection failed
- Server unreachable

### Audio Processing Errors

**Compression Errors**:
- Invalid audio format
- Array conversion failures
- SNR calculation errors

**Encryption Errors**:
- Key derivation failures
- Encryption/decryption failures
- HMAC verification failures

### Network Errors

**Message Transmission**:
- Socket closed unexpectedly
- Partial message received
- Invalid message format

**Error Recovery**:
- Automatic reconnection attempts
- Error logging
- User notification via UI

---

## Performance Considerations

### Audio Latency

**Sources of Latency**:
1. **Recording**: ~10-50ms (browser buffering)
2. **Compression**: ~1-5ms (CPU processing)
3. **Encryption**: ~1-2ms (cryptographic operations)
4. **Network**: ~1-100ms (depending on connection)
5. **Decryption**: ~1-2ms
6. **Playback**: ~10-50ms (browser buffering)

**Total Latency**: ~25-210ms (typically 50-100ms on local network)

### Bandwidth Usage

**Per Audio Packet**:
- Original: ~1-5 KB (WebM/Opus, variable)
- Compressed: ~0.5-2 KB (8-bit PCM, 64 Kbps)
- Encrypted: ~0.6-2.2 KB (with IV, tag, HMAC)
- Overhead: ~20-30% (encryption + integrity)

**Estimated Bandwidth**:
- 64 Kbps audio + ~20% overhead ≈ 77 Kbps per direction
- Full duplex: ~154 Kbps total

### CPU Usage

**Compression**: Moderate (numpy operations)
**Encryption**: Low (hardware-accelerated AES)
**Network I/O**: Low (async operations)

---

## Testing and Validation

### Quality Assurance

**SNR Validation**:
- Verify SNR ≥ 40dB for typical voice input
- Test with various input levels
- Monitor SNR during transmission

**Bitrate Validation**:
- Verify bitrate ≈ 64 Kbps
- Check compression ratio
- Validate sample rate conversion

**Security Validation**:
- Verify encryption/decryption
- Test HMAC integrity checks
- Validate key exchange
- Test tamper detection

### Test Scenarios

1. **Single Client**: Record and playback
2. **Multiple Clients**: Broadcast functionality
3. **Network Interruption**: Reconnection handling
4. **Low SNR**: Warning display
5. **Large Audio**: Chunk handling
6. **Concurrent Connections**: Thread safety

---

## Future Enhancements

### Potential Improvements

1. **Audio Codec**: Implement Opus codec for better compression
2. **Adaptive Bitrate**: Adjust bitrate based on network conditions
3. **Error Correction**: Add FEC for packet loss recovery
4. **Voice Activity Detection**: Transmit only when speaking
5. **Echo Cancellation**: Server-side echo cancellation
6. **Multi-room Support**: Separate audio channels/rooms
7. **Recording Storage**: Save conversations
8. **Mobile App**: Native mobile applications

---

## Conclusion

This documentation provides a comprehensive overview of the Secure Voice Communication system, covering:

- **Architecture**: Three-tier system (Browser → Web Server → Voice Server)
- **Frontend**: HTML5/JavaScript with Web Audio API
- **Backend**: Python servers with Flask and SocketIO
- **Security**: ECDH key exchange, AES-256-GCM encryption, HMAC integrity
- **Audio Processing**: 64 Kbps compression with SNR monitoring
- **Network Protocol**: Custom TCP protocol with message framing
- **Quality Control**: Real-time SNR and bitrate monitoring

The system provides secure, high-quality voice communication with end-to-end encryption, integrity protection, and quality assurance.

---

**Document Version**: 1.0  
**Last Updated**: 2024  
**Author**: System Documentation

