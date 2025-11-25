#!/bin/bash

# Stop script for Secure Voice Communication servers
# This script stops both the voice server and web server

echo "=========================================="
echo "Stopping Secure Voice Communication Servers"
echo "=========================================="
echo ""

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Stop by PID files if they exist
if [ -f .voice_server.pid ]; then
    VOICE_PID=$(cat .voice_server.pid)
    if ps -p $VOICE_PID > /dev/null 2>&1; then
        echo "Stopping voice server (PID: $VOICE_PID)..."
        kill $VOICE_PID 2>/dev/null
        sleep 1
        if ps -p $VOICE_PID > /dev/null 2>&1; then
            kill -9 $VOICE_PID 2>/dev/null
        fi
        echo "Voice server stopped"
    else
        echo "Voice server was not running (PID: $VOICE_PID)"
    fi
    rm -f .voice_server.pid
else
    echo "No voice server PID file found"
fi

if [ -f .web_server.pid ]; then
    WEB_PID=$(cat .web_server.pid)
    if ps -p $WEB_PID > /dev/null 2>&1; then
        echo "Stopping web server (PID: $WEB_PID)..."
        kill $WEB_PID 2>/dev/null
        sleep 1
        if ps -p $WEB_PID > /dev/null 2>&1; then
            kill -9 $WEB_PID 2>/dev/null
        fi
        echo "Web server stopped"
    else
        echo "Web server was not running (PID: $WEB_PID)"
    fi
    rm -f .web_server.pid
else
    echo "No web server PID file found"
fi

# Also try to stop by process name (fallback)
echo ""
echo "Checking for any remaining processes..."

VOICE_PROCESSES=$(pgrep -f "run_server.py" 2>/dev/null)
if [ ! -z "$VOICE_PROCESSES" ]; then
    echo "Found voice server processes, stopping..."
    pkill -f "run_server.py"
    sleep 1
    pkill -9 -f "run_server.py" 2>/dev/null
    echo "Voice server processes stopped"
fi

WEB_PROCESSES=$(pgrep -f "run_web_server.py" 2>/dev/null)
if [ ! -z "$WEB_PROCESSES" ]; then
    echo "Found web server processes, stopping..."
    pkill -f "run_web_server.py"
    sleep 1
    pkill -9 -f "run_web_server.py" 2>/dev/null
    echo "Web server processes stopped"
fi

# Check ports
if lsof -Pi :8888 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "Port 8888 is still in use"
else
    echo "Port 8888 is free"
fi

if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "Port 5000 is still in use"
else
    echo "Port 5000 is free"
fi

echo ""
echo "=========================================="
echo "All servers stopped"
echo "=========================================="

