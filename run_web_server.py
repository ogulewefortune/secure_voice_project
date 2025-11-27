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
        # Try multiple common gateway addresses
        for gateway in ['8.8.8.8', '1.1.1.1', '10.254.254.254']:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1)
                s.connect((gateway, 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith('127.'):
                    return ip
            except Exception:
                continue
        return '127.0.0.1'
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
                    # macOS: use ipconfig getifaddr
                    import platform
                    if platform.system() == 'Darwin':  # macOS
                        # Try Wi-Fi interface (en0) first, then Ethernet (en1)
                        for interface in ['en0', 'en1', 'en2']:
                            result = subprocess.run(['ipconfig', 'getifaddr', interface], capture_output=True, text=True)
                            if result.returncode == 0 and result.stdout.strip():
                                ip = result.stdout.strip()
                                if not ip.startswith('127.'):
                                    return ip
                        # Fallback: use ifconfig
                        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                        if result.returncode == 0:
                            import re
                            # Look for inet addresses (not loopback)
                            matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                            for match in matches:
                                if not match.startswith('127.'):
                                    return match
                    else:
                        # Linux: use hostname -I
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
    log("INTEGRATED SERVER (All-in-One):")
    log(f"  Web Interface:  http://{local_ip}:5000")
    log(f"  Voice Server:   Integrated (port 8888)")
    log("")
    log("=" * 70)
    log("TO CONNECT FROM ANOTHER DEVICE:")
    log(f"  1. Open browser on the other device")
    log(f"  2. Go to: http://{local_ip}:5000")
    log(f"  3. Click 'Connect to Server' - no need to enter IP/port!")
    log("")
    log("NOTE: Voice server is integrated - no need to run run_server.py separately!")
    log("")
    log("IMPORTANT - macOS Firewall:")
    log("  If devices can't connect, check macOS Firewall:")
    log("  System Settings > Network > Firewall > Options")
    log("  Allow incoming connections for Python, or disable firewall")
    log("  Make sure ports 5000 and 8888 are not blocked")
    log("")
    log("Press Ctrl+C to stop the server")
    log("=" * 70)
    log("")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

