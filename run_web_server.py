#!/usr/bin/env python3
"""
Web server launcher script.
"""

import socket
import subprocess
from web_server import app, socketio

def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('10.254.254.254', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip
    except Exception:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip == '127.0.0.1':
                result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    ip = result.stdout.strip().split()[0]
            return ip
        except Exception:
            return '127.0.0.1'

if __name__ == '__main__':
    from datetime import datetime
    
    def log(message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    local_ip = get_local_ip()
    log("=" * 60)
    log("Secure Voice Communication - Web Interface")
    log("=" * 60)
    log("Starting web server...")
    log(f"Local access:  http://localhost:5000")
    log(f"Network access: http://{local_ip}:5000")
    log("")
    log("To connect from another device on the same network:")
    log(f"  Open browser and go to: http://{local_ip}:5000")
    log("")
    log("Make sure the voice server is running on port 8888")
    log("(Run 'python3 run_server.py' in another terminal)")
    log("Press Ctrl+C to stop the web server")
    log("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

