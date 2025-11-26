# Troubleshooting Connection Issues

## Problem: Cannot Connect from Mac to Lenovo (Windows) Server

### Common Causes:

1. **Windows Firewall Blocking Port 8888** (Most Common)
2. **Wrong IP Address**
3. **Server Not Running**
4. **Network Issues**

---

## Step-by-Step Troubleshooting

### On the Server (Lenovo - Windows):

#### 1. Verify Server is Running
```bash
python3 run_server.py
```
- You should see: "Server started on 0.0.0.0:8888"
- Note the IP address displayed (e.g., `192.168.1.100`)

#### 2. Check Windows Firewall (IMPORTANT!)

**Option A: Allow Port Through Firewall (Recommended)**
1. Open Windows Defender Firewall
2. Click "Advanced settings"
3. Click "Inbound Rules" → "New Rule"
4. Select "Port" → Next
5. Select "TCP" and enter port `8888` → Next
6. Select "Allow the connection" → Next
7. Check all profiles (Domain, Private, Public) → Next
8. Name it "Voice Server Port 8888" → Finish

**Option B: Temporarily Disable Firewall (For Testing Only)**
1. Open Windows Defender Firewall
2. Click "Turn Windows Defender Firewall on or off"
3. Turn off for Private networks (temporarily)
4. **Remember to turn it back on after testing!**

#### 3. Verify Server IP Address
- Run `ipconfig` in Command Prompt
- Look for "IPv4 Address" under your active network adapter
- Use this IP address (not 127.0.0.1 or localhost)

#### 4. Test Server is Listening
- Open Command Prompt as Administrator
- Run: `netstat -an | findstr 8888`
- You should see: `0.0.0.0:8888` or `[::]:8888` in LISTENING state

---

### On Your Mac (Client):

#### 1. Verify Network Connectivity
```bash
ping <server-ip>
```
- Replace `<server-ip>` with the Lenovo's IP address
- If ping fails, you're not on the same network

#### 2. Check IP Address
- Make sure you're using the correct IP from the server
- Don't use `localhost` or `127.0.0.1` - use the actual network IP

#### 3. Test Port Connection
```bash
nc -zv <server-ip> 8888
```
- If connection succeeds, port is open
- If connection refused, firewall is blocking

---

## Quick Checklist

- [ ] Voice server is running on Lenovo (`python3 run_server.py`)
- [ ] Windows Firewall allows port 8888 (or firewall is temporarily disabled)
- [ ] Using correct IP address (not localhost)
- [ ] Both devices on same network (same Wi-Fi/router)
- [ ] Port 8888 is not blocked by router/network admin
- [ ] Web server is running on Lenovo (`python3 run_web_server.py`)

---

## Common Error Messages

### "Connection refused" or "[Errno 61]"
- **Cause**: Firewall blocking or server not running
- **Fix**: Check Windows Firewall and verify server is running

### "Connection timeout"
- **Cause**: Wrong IP address or network issue
- **Fix**: Verify IP address and network connectivity

### "No route to host"
- **Cause**: Network unreachable
- **Fix**: Check both devices are on same network

---

## Still Having Issues?

1. **Try connecting from the server machine itself:**
   - On Lenovo, open browser: `http://localhost:5000`
   - Enter Server Host: `localhost` or `127.0.0.1`
   - If this works, the issue is network/firewall related

2. **Check router settings:**
   - Some routers block inter-device communication
   - Check if "AP Isolation" or "Client Isolation" is enabled
   - Disable it if enabled

3. **Try different port:**
   - If port 8888 is blocked, try changing to a different port
   - Update both server and client to use the new port

