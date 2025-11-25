#!/bin/bash

# Start script for Secure Voice Communication servers
# This script starts both the voice server and web server

echo "=========================================="
echo "Starting Secure Voice Communication"
echo "=========================================="
echo ""

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check if servers are already running
if lsof -Pi :8888 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "Voice server is already running on port 8888"
    read -p "Do you want to stop it and restart? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping existing voice server..."
        pkill -f "run_server.py"
        sleep 1
    else
        echo "Keeping existing server running"
    fi
fi

if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "Web server is already running on port 5000"
    read -p "Do you want to stop it and restart? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Stopping existing web server..."
        pkill -f "run_web_server.py"
        sleep 1
    else
        echo "Keeping existing server running"
    fi
fi

# Start voice server in background
echo "Starting voice server on port 8888..."
python3 run_server.py > server.log 2>&1 &
VOICE_SERVER_PID=$!
echo "   Voice server PID: $VOICE_SERVER_PID"
sleep 2

# Check if voice server started successfully
if ps -p $VOICE_SERVER_PID > /dev/null; then
    echo "Voice server started successfully"
else
    echo "Failed to start voice server. Check server.log for details."
    exit 1
fi

# Start web server in background
echo "Starting web server on port 5000..."
python3 run_web_server.py > web_server.log 2>&1 &
WEB_SERVER_PID=$!
echo "   Web server PID: $WEB_SERVER_PID"
sleep 2

# Check if web server started successfully
if ps -p $WEB_SERVER_PID > /dev/null; then
    echo "Web server started successfully"
else
    echo "Failed to start web server. Check web_server.log for details."
    kill $VOICE_SERVER_PID 2>/dev/null
    exit 1
fi

echo ""
echo "=========================================="
echo "Both servers are running!"
echo "=========================================="
echo ""
echo "Voice Server:  http://localhost:8888 (PID: $VOICE_SERVER_PID)"
echo "Web Interface: http://localhost:5000 (PID: $WEB_SERVER_PID)"
echo ""
echo "Logs:"
echo "  - Voice server: tail -f server.log"
echo "  - Web server:   tail -f web_server.log"
echo ""
echo "To stop servers, run: ./stop_servers.sh"
echo "Or press Ctrl+C and run: ./stop_servers.sh"
echo ""

# Save PIDs to file for stop script
echo "$VOICE_SERVER_PID" > .voice_server.pid
echo "$WEB_SERVER_PID" > .web_server.pid

# Keep script running to show logs
echo "Press Ctrl+C to stop viewing logs (servers will keep running)"
echo "=========================================="
echo ""

# Tail both log files
tail -f server.log web_server.log

