# Two-Way Communication Guide

## Overview

The Secure Voice Communication system supports real-time two-way communication between multiple clients. When you send audio, it is broadcast to all other connected clients, and you can receive and play audio from other clients.

## How It Works

### Architecture

1. **Server Broadcasting**: The voice server receives audio from one client and broadcasts it to all other connected clients
2. **Per-Client Encryption**: Each client has a unique encryption key, so the server re-encrypts audio for each recipient
3. **Real-Time Delivery**: Audio messages are delivered in real-time via WebSocket connections

### Communication Flow

```
Client A (You)                    Voice Server                    Client B (Other)
     |                                 |                                |
     |---[Record Audio]--------------->|                                |
     |                                 |                                |
     |---[Encrypt with A's key]------->|                                |
     |                                 |                                |
     |                                 |---[Decrypt with A's key]       |
     |                                 |                                |
     |                                 |---[Re-encrypt with B's key]--->|
     |                                 |                                |
     |                                 |                            [Receive & Play]
```

## Using Two-Way Communication

### Step 1: Start the Servers

**Terminal 1 - Voice Server:**
```bash
python3 run_server.py
```

**Terminal 2 - Web Server:**
```bash
python3 run_web_server.py
```

### Step 2: Open Multiple Browser Windows/Tabs

1. Open your browser to `http://localhost:5000`
2. Open a second browser window/tab (or use a different browser/incognito window) to `http://localhost:5000`
3. Each window represents a different client

### Step 3: Connect Both Clients

1. In **Client 1** (first window):
   - Click "Connect to Server"
   - Wait for "Connected to voice server" status

2. In **Client 2** (second window):
   - Click "Connect to Server"
   - Wait for "Connected to voice server" status

### Step 4: Send Audio from Client 1

1. In **Client 1**:
   - Click "Start Recording"
   - Speak into your microphone
   - Click "Stop Recording"
   - Click "Send Audio"

### Step 5: Receive Audio in Client 2

1. In **Client 2**, you will see:
   - **Connection Status Panel**: Shows "Active Clients: 2" (or more if others are connected)
   - **Received Messages Panel**: A new message appears with:
     - Timestamp
     - Packet number
     - File size
     - "Play" button

2. Click the **"Play"** button to hear the audio message

### Step 6: Respond from Client 2

1. In **Client 2**:
   - Click "Start Recording"
   - Speak your response
   - Click "Stop Recording"
   - Click "Send Audio"

2. **Client 1** will receive the message in their "Received Messages" panel

## Features

### Connection Status Panel

The **Connection Status** panel (right side) shows:
- **Connection Status**: Connected/Disconnected indicator
- **Active Clients**: Number of clients currently connected to the server
- **Messages Sent**: Count of messages you've sent
- **Messages Received**: Count of messages you've received

### Received Messages Panel

The **Received Messages** panel shows:
- **Message List**: All received audio messages (last 20)
- **Message Details**: 
  - Timestamp (when received)
  - Packet number
  - File size (KB)
  - Encryption info
- **Play Button**: Click to play each message
- **Auto-Notifications**: Browser notifications when new messages arrive (if permission granted)

### Message Features

- **Visual Feedback**: New messages slide in with animation
- **Playback Control**: Each message has its own play button
- **Message History**: Keeps last 20 messages
- **Real-Time Updates**: Messages appear immediately when received

## Testing with Multiple Clients

### Method 1: Multiple Browser Windows

1. Open multiple browser windows to `http://localhost:5000`
2. Connect each one to the server
3. Send messages between them

### Method 2: Different Devices

1. Find your computer's IP address:
   ```bash
   # On Mac/Linux
   ifconfig | grep "inet "
   
   # On Windows
   ipconfig
   ```

2. On another device on the same network:
   - Open browser to `http://YOUR_IP:5000`
   - Connect and communicate

### Method 3: Command Line Client

You can also use the command-line client:

```bash
# Terminal 3 - Client 1
python3 run_client.py

# Terminal 4 - Client 2  
python3 run_client.py
```

## How to Know if Someone Received Your Message

### Visual Indicators

1. **Status Bar**: Shows "Audio transmitted successfully" when sent
2. **Messages Sent Counter**: Increments in Connection Status panel
3. **Server Console**: Shows "Broadcasted to X client(s)" when server broadcasts

### Delivery Confirmation

- When you send audio, the server broadcasts it to all connected clients
- The server logs show how many clients received the message
- If no other clients are connected, your message won't be received by anyone (but it's still sent to the server)

## Troubleshooting

### No Messages Received

1. **Check Active Clients**: Look at "Active Clients" count - should be > 1
2. **Check Server Console**: Verify server shows "Broadcasted to X client(s)"
3. **Check Connection**: Ensure both clients show "Connected to server"
4. **Check Browser Console**: Look for errors in F12 Developer Tools

### Messages Not Playing

1. **Check Audio Permissions**: Browser may need permission to play audio
2. **Check Browser Console**: Look for audio playback errors
3. **Try Different Browser**: Some browsers have stricter audio policies

### Can't See Other Clients

- The "Active Clients" count is an estimate
- The server doesn't currently send exact client counts to web clients
- You'll know clients are connected when you receive messages from them

## Security Features

All messages are:
- **Encrypted**: AES-256-GCM encryption per client
- **Verified**: HMAC integrity checks
- **Authenticated**: GCM authentication tags prevent tampering
- **Isolated**: Each client has a unique encryption key

## Example Session

```
Client 1: [Connects] → "Connected to voice server"
Client 2: [Connects] → "Connected to voice server"

Client 1: [Records] → "Hello, can you hear me?"
Client 1: [Sends] → Status: "Audio transmitted successfully"

Client 2: [Receives] → New message appears in "Received Messages"
Client 2: [Plays] → Hears "Hello, can you hear me?"

Client 2: [Records] → "Yes, I can hear you!"
Client 2: [Sends] → Status: "Audio transmitted successfully"

Client 1: [Receives] → New message appears
Client 1: [Plays] → Hears "Yes, I can hear you!"
```

## Tips

1. **Wait for Connection**: Make sure both clients are connected before sending
2. **Check Status**: Monitor the Connection Status panel for active clients
3. **Use Headphones**: Prevents feedback when playing received audio
4. **Monitor Console**: Server console shows detailed broadcast information
5. **Test Locally First**: Use multiple browser windows to test before using different devices

