# Testing Security Alerts

This guide explains how to test the intrusion detection system and see security alerts in real-time.

## Prerequisites

1. **Start the servers**:
   ```bash
   # Terminal 1: Start voice server
   python3 run_server.py
   
   # Terminal 2: Start web server
   python3 run_web_server.py
   ```

2. **Open the web interface**:
   - Open your browser to `http://localhost:5000`
   - Connect to the server
   - You should see the "Security Alerts" panel on the right side

## Running Attack Tests

### Method 1: Live Attack Script (Recommended)

Run the live attack script that connects to your running server:

```bash
python3 test_live_attacks.py
```

This script will:
1. Connect to your running server
2. Perform various attacks (eavesdropping, imposter client, MITM)
3. Trigger security alerts
4. Show alerts in the web interface

**Watch the Security Alerts panel** in your browser - alerts should appear in real-time!

### Method 2: Manual Testing

#### Test 1: Eavesdropping Attack

1. Connect to the server normally
2. Send encrypted audio
3. Try to decrypt with wrong key (will fail)
4. **Alert**: EAVESDROPPING (HIGH severity)

#### Test 2: Imposter Client Attack

1. Connect with invalid public key
2. Fail key exchange multiple times
3. **Alert**: IMPOSTER_CLIENT (MEDIUM severity)

#### Test 3: MITM Attack

1. Connect normally
2. Modify encrypted message (flip bits)
3. Send modified message
4. Server tries to decrypt and fails
5. **Alert**: MAN_IN_THE_MIDDLE (CRITICAL severity)

#### Test 4: Message Tampering

1. Connect normally
2. Send message with corrupted HMAC
3. **Alert**: INTEGRITY_VIOLATION (CRITICAL severity)

## What to Look For

### In the Web Interface

1. **Security Alerts Panel** (right side):
   - Shows real-time alerts
   - Color-coded by severity:
     - RED: CRITICAL alerts
     - ORANGE: HIGH alerts
     - YELLOW: MEDIUM alerts
     - GREEN: LOW alerts

2. **Alert Count Badge**:
   - Shows number of active alerts
   - Updates in real-time

3. **Alert Details**:
   - Threat type (EAVESDROPPING, IMPOSTER_CLIENT, etc.)
   - Severity level
   - Timestamp
   - Source IP (if available)
   - Attack Description: What type of attack was detected
   - What Attacker Tried: Specific actions the attacker attempted
   - Protection: How the system protected against the attack

### In the Server Console

You should see log messages like:
```
[19:54:18] [ALERT] SECURITY ALERT: [CRITICAL] MAN_IN_THE_MIDDLE: Authentication failure detected from 127.0.0.1
```

## Troubleshooting

### Alerts Not Appearing

1. **Check server is running**: Make sure `run_server.py` is running
2. **Check web server is running**: Make sure `run_web_server.py` is running
3. **Check browser console**: Open browser DevTools (F12) and check for errors
4. **Check SocketIO connection**: Look for connection messages in browser console
5. **Refresh the page**: Sometimes alerts don't load on initial page load

### Alerts Appear But Not Real-Time

1. **Check SocketIO**: Make sure SocketIO is connected (check browser console)
2. **Check alert callbacks**: Verify `handle_security_alert` is registered
3. **Check broadcast**: Verify `socketio.emit('security_alert', ...)` is called

### No Alerts When Running Tests

1. **Verify test connects to correct server**: Check host/port in test script
2. **Verify attacks trigger detection**: Check server logs for error messages
3. **Verify IDS is initialized**: Check that `get_ids()` is called in server
4. **Check alert thresholds**: Some attacks need multiple attempts

## Expected Behavior

### Successful Attack Detection

When an attack is detected:
1. Alert appears in Security Alerts panel
2. Alert count badge updates
3. Server console shows alert log
4. Alert includes detailed attack information:
   - Attack Description
   - What Attacker Tried
   - Protection Mechanism
5. Critical alerts may trigger browser notification

### Attack Types and Alerts

| Attack Type | Trigger | Alert Type | Severity |
|------------|---------|------------|----------|
| Eavesdropping | Wrong decryption key | EAVESDROPPING | HIGH |
| Imposter Client | Failed key exchange | IMPOSTER_CLIENT | MEDIUM |
| MITM | Modified message | MAN_IN_THE_MIDDLE | CRITICAL |
| Tampering | HMAC failure | INTEGRITY_VIOLATION | CRITICAL |
| Suspicious Activity | Rapid connections | SUSPICIOUS_ACTIVITY | MEDIUM |

## Example Test Session

```bash
# Terminal 1: Start voice server
$ python3 run_server.py
[19:54:00] [INFO] Server started on localhost:8888

# Terminal 2: Start web server
$ python3 run_web_server.py
[19:54:05] [INFO] Starting web server on http://localhost:5000

# Terminal 3: Run attack tests
$ python3 test_live_attacks.py

# Browser: Watch Security Alerts panel
# You should see alerts appear as attacks are performed!
```

## Next Steps

- Review alerts in the Security Alerts panel
- Check alert details for threat information
- Monitor alert count over time
- Investigate repeated attacks from same IP
- Adjust detection thresholds if needed

---

**Note**: The test script connects to the running server, so make sure both servers are running before testing!

