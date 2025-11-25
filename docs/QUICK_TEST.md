# Quick Test Guide - Security Alerts

## Quick Start (3 Steps)

### Step 1: Start Servers
```bash
# Terminal 1
python3 run_server.py

# Terminal 2  
python3 run_web_server.py
```

### Step 2: Open Browser
- Go to: `http://localhost:5000`
- Click "Connect to Server"
- Look for "Security Alerts" panel on the right

### Step 3: Run Attack Test
```bash
# Terminal 3
python3 test_live_attacks.py
```

**Watch the Security Alerts panel** - alerts should appear!

## What You Should See

### In Browser (Security Alerts Panel):
- **CRITICAL** alerts (red) - MITM attacks, tampering
- **HIGH** alerts (orange) - Eavesdropping attempts  
- **MEDIUM** alerts (yellow) - Imposter clients, suspicious activity
- **LOW** alerts (green) - Minor suspicious activity

Each alert shows:
- Attack Description: What type of attack was detected
- What Attacker Tried: Specific actions the attacker attempted
- Protection: How the system protected against the attack

### In Server Console:
```
[19:54:18] [ALERT] SECURITY ALERT: [CRITICAL] MAN_IN_THE_MIDDLE: Authentication failure...
```

## If Alerts Don't Appear

1. Check both servers are running
2. Check browser console for errors (F12)
3. Refresh browser page
4. Verify SocketIO connection (check browser console)
5. Check server logs for error messages

## Test Different Attacks

The `test_live_attacks.py` script tests:
- Eavesdropping (wrong key)
- Imposter client (invalid key exchange)
- MITM (modified message)
- Key exchange failures

Each attack should trigger a different alert type!

---

**Tip**: Keep the browser open and watch alerts appear in real-time as attacks happen!

