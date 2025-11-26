#!/usr/bin/env python3
"""
Web server launcher script.
"""

import socket
import subprocess
from web_server import app, socketio

def get_local_ip():
    """Get the local IP address of this machine (cross-platform)."""
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
            import platform
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip == '127.0.0.1' or ip.startswith('127.'):
                # Try alternative method for Windows/Linux
                if platform.system() == 'Windows':
                    # Windows: use ipconfig equivalent
                    result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
                    if result.returncode == 0:
                        # Parse IPv4 address from ipconfig output
                        import re
                        matches = re.findall(r'IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
                        if matches:
                            # Return first non-loopback address
                            for match in matches:
                                if not match.startswith('127.'):
                                    return match
                else:
                    # Linux/Mac: use hostname -I
                    result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        ip = result.stdout.strip().split()[0]
                        if not ip.startswith('127.'):
                            return ip
            return ip
        except Exception:
            return '127.0.0.1'

if __name__ == '__main__':
    from datetime import datetime
    
    def log(message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    local_ip = get_local_ip()
    log("")
    log("=" * 70)
    log(" " * 20 + "SECURE VOICE COMMUNICATION SERVER")
    log("=" * 70)
    log("")
    log("SERVER IP ADDRESS FOR OTHER DEVICES:")
    log(" " * 10 + f"  >>>  {local_ip}  <<<")
    log("")
    log("=" * 70)
    log("WEB SERVER (Port 5000):")
    log(f"  Local access:   http://localhost:5000")
    log(f"  Network access: http://{local_ip}:5000")
    log("")
    log("VOICE SERVER (Port 8888):")
    log(f"  Server IP:      {local_ip}")
    log(f"  Port:           8888")
    log("")
    log("=" * 70)
    log("TO CONNECT FROM ANOTHER DEVICE:")
    log(f"  1. Open browser on the other device")
    log(f"  2. Go to: http://{local_ip}:5000")
    log(f"  3. Enter Server Host: {local_ip}")
    log(f"  4. Enter Server Port: 8888")
    log("")
    log("Make sure the voice server is running on port 8888")
    log("(Run 'python3 run_server.py' in another terminal)")
    log("Press Ctrl+C to stop the web server")
    log("=" * 70)
    log("")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

