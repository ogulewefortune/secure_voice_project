# How to Start the Secure Voice Communication Project

## Quick Start Commands

### Step 1: Start the Voice Server
Open Terminal 1 and run:
```bash
cd /Users/fortuneogulewe/Documents/secure_voice_project
python3 run_server.py
```

You should see:
```
[HH:MM:SS] [INFO] ============================================================
[HH:MM:SS] [INFO] Secure Voice Communication Server
[HH:MM:SS] [INFO] ============================================================
[HH:MM:SS] [INFO] Server started on localhost:8888
[HH:MM:SS] [INFO] Waiting for clients...
[HH:MM:SS] [INFO] ============================================================
[HH:MM:SS] [INFO] Server key pair generated (ECDH)
```

### Step 2: Start the Web Server
Open Terminal 2 and run:
```bash
cd /Users/fortuneogulewe/Documents/secure_voice_project
python3 run_web_server.py
```

You should see:
```
[HH:MM:SS] [INFO] ============================================================
[HH:MM:SS] [INFO] Secure Voice Communication - Web Interface
[HH:MM:SS] [INFO] ============================================================
[HH:MM:SS] [INFO] Starting web server on http://localhost:5000
[HH:MM:SS] [INFO] Open your browser and navigate to: http://localhost:5000
[HH:MM:SS] [INFO] Make sure the voice server is running on port 8888
[HH:MM:SS] [INFO] ============================================================
```

### Step 3: Open in Browser
Open your browser and go to:
```
http://localhost:5000
```

## What You'll See in the Terminal

### Voice Server Terminal (Terminal 1)
- Client connections
- Key exchange process
- Audio packet receiving and broadcasting
- Client disconnections

Example output:
```
[14:30:15] [CONNECT] New client connecting from 127.0.0.1:52341
[14:30:15] [KEY_EXCHANGE] [127.0.0.1:52341] Starting key exchange...
[14:30:15] [KEY_EXCHANGE] [127.0.0.1:52341] Sent server public key
[14:30:15] [KEY_EXCHANGE] [127.0.0.1:52341] Received client public key
[14:30:15] [SECURE] [127.0.0.1:52341] Secure connection established (AES-256-GCM)
[14:30:15] [STATUS] [127.0.0.1:52341] Active clients: 1
[14:30:20] [RECEIVE] [127.0.0.1:52341] Received audio packet #1 (1234 bytes encrypted, 1024 bytes decrypted)
[14:30:20] [SEND] [127.0.0.1:52341] Broadcasted to 0 client(s)
```

### Web Server Terminal (Terminal 2)
- Web client connections
- Voice server connections
- Audio processing (compression, encryption)
- Quality metrics (SNR, bitrate)
- Audio sending and receiving

Example output:
```
[14:30:15] [CONNECT] Web client connected: a1b2c3d4...
[14:30:15] [CONNECT] [a1b2c3d4] Connecting to voice server at localhost:8888...
[14:30:15] [CONNECT] [a1b2c3d4] Successfully connected to voice server
[14:30:20] [PROCESS] [a1b2c3d4] Processing audio: 2048 bytes
[14:30:20] [QUALITY] [a1b2c3d4] SNR: 48.19dB (meets ≥40dB requirement)
[14:30:20] [COMPRESS] [a1b2c3d4] Compression: 2048 → 1024 bytes (50.0% reduction)
[14:30:20] [QUALITY] [a1b2c3d4] Bitrate: 64.0 Kbps (target: 64.0 Kbps)
[14:30:20] [SECURITY] [a1b2c3d4] Added HMAC integrity check
[14:30:20] [SECURITY] [a1b2c3d4] Encrypted: 1024 → 1234 bytes (AES-256-GCM)
[14:30:20] [SEND] [a1b2c3d4] Sent audio packet to server (1234 bytes)
[14:30:25] [RECEIVE] [a1b2c3d4] Received audio packet (1234 bytes encrypted)
[14:30:25] [SECURITY] [a1b2c3d4] Decrypted: 1234 → 1024 bytes
[14:30:25] [SECURITY] [a1b2c3d4] Integrity verified (1024 bytes)
[14:30:25] [SEND] [a1b2c3d4] Forwarded audio to web client
```

## Activity Indicators

- Receiving data
- Sending data
- Security operation (encryption/decryption)
- Encryption
- Decryption
- Success/Pass
- Warning
- Error
- Quality/metrics

## Stopping the Servers

Press `Ctrl+C` in each terminal to stop the servers gracefully.

