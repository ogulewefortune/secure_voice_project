# Server Start/Stop Commands

## Quick Start & Stop

### Option 1: Using Shell Scripts (Recommended)

**Start both servers:**
```bash
./start_servers.sh
```

**Stop both servers:**
```bash
./stop_servers.sh
```

### Option 2: Using Python Scripts

**Start both servers:**
```bash
python3 start_servers.py
```

**Stop both servers:**
```bash
python3 stop_servers.py
```

### Option 3: Manual Start (Separate Terminals)

**Terminal 1 - Start Voice Server:**
```bash
python3 run_server.py
```

**Terminal 2 - Start Web Server:**
```bash
python3 run_web_server.py
```

**To stop:** Press `Ctrl+C` in each terminal

## What the Scripts Do

### Start Scripts:
- Check if servers are already running
- Ask if you want to restart existing servers
- Start voice server on port 8888
- Start web server on port 5000
- Save process IDs (PIDs) for easy stopping
- Show server status and log locations

### Stop Scripts:
- Stop servers using saved PIDs
- Fallback to process name matching if PIDs not found
- Verify ports are free
- Clean up PID files

## Viewing Logs

While servers are running, you can view logs:

```bash
# Voice server logs
tail -f server.log

# Web server logs
tail -f web_server.log

# Both logs together
tail -f server.log web_server.log
```

## Troubleshooting

**If ports are still in use after stopping:**
```bash
# Kill processes on specific ports
lsof -ti:8888 | xargs kill -9
lsof -ti:5000 | xargs kill -9
```

**Check if servers are running:**
```bash
# Check voice server
lsof -i :8888

# Check web server
lsof -i :5000

# Check all Python processes
ps aux | grep -E "(run_server|run_web_server)"
```

## Server URLs

- **Voice Server:** http://localhost:8888 (internal, not for browser)
- **Web Interface:** http://localhost:5000 (open in browser)

