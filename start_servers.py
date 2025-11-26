#!/usr/bin/env python3
"""
Python script to start both servers.
Run: python3 start_servers.py
"""

import subprocess
import sys
import time
import os
import signal
import socket
from pathlib import Path

def check_port(port):
    """Check if a port is in use."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('localhost', port))
    sock.close()
    return result == 0

def start_servers():
    """Start both voice server and web server."""
    print("=" * 60)
    print("Starting Secure Voice Communication Servers")
    print("=" * 60)
    print()
    
    # Check if servers are already running
    if check_port(8888):
        print("Voice server is already running on port 8888")
        response = input("Do you want to stop it and restart? (y/n): ")
        if response.lower() == 'y':
            print("Stopping existing voice server...")
            subprocess.run(["pkill", "-f", "run_server.py"], 
                         capture_output=True)
            time.sleep(1)
        else:
            print("Keeping existing server running")
    
    if check_port(5000):
        print("Web server is already running on port 5000")
        response = input("Do you want to stop it and restart? (y/n): ")
        if response.lower() == 'y':
            print("Stopping existing web server...")
            subprocess.run(["pkill", "-f", "run_web_server.py"], 
                         capture_output=True)
            time.sleep(1)
        else:
            print("Keeping existing server running")
    
    # Start voice server
    print("\nStarting voice server on port 8888...")
    voice_server = subprocess.Popen(
        [sys.executable, "run_server.py"],
        stdout=open("server.log", "w"),
        stderr=subprocess.STDOUT
    )
    print(f"   Voice server PID: {voice_server.pid}")
    time.sleep(2)
    
    if voice_server.poll() is None:
        print("Voice server started successfully")
    else:
        print("Failed to start voice server. Check server.log for details.")
        return False
    
    # Start web server
    print("Starting web server on port 5000...")
    web_server = subprocess.Popen(
        [sys.executable, "run_web_server.py"],
        stdout=open("web_server.log", "w"),
        stderr=subprocess.STDOUT
    )
    print(f"   Web server PID: {web_server.pid}")
    time.sleep(2)
    
    if web_server.poll() is None:
        print("Web server started successfully")
    else:
        print("Failed to start web server. Check web_server.log for details.")
        voice_server.terminate()
        return False
    
    # Save PIDs
    with open(".voice_server.pid", "w") as f:
        f.write(str(voice_server.pid))
    with open(".web_server.pid", "w") as f:
        f.write(str(web_server.pid))
    
    # Get local IP address for network access
    def get_local_ip():
        """Get the local IP address of this machine."""
        try:
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
                    import subprocess
                    result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
                    if result.returncode == 0 and result.stdout.strip():
                        ip = result.stdout.strip().split()[0]
                return ip
            except Exception:
                return '127.0.0.1'
    
    local_ip = get_local_ip()
    
    print()
    print("=" * 60)
    print("Both servers are running!")
    print("=" * 60)
    print()
    print(f"Voice Server:")
    print(f"  Local:  http://localhost:8888")
    print(f"  Network: http://{local_ip}:8888")
    print()
    print(f"Web Interface:")
    print(f"  Local:  http://localhost:5000")
    print(f"  Network: http://{local_ip}:5000")
    print()
    print(f"To connect from another device on the same network:")
    print(f"  Open browser and go to: http://{local_ip}:5000")
    print()
    print("Logs:")
    print("  - Voice server: tail -f server.log")
    print("  - Web server:   tail -f web_server.log")
    print()
    print("To stop servers:")
    print("  - Press Ctrl+C (then run: python3 stop_servers.py)")
    print("  - Or run: python3 stop_servers.py")
    print()
    print("=" * 60)
    print("Press Ctrl+C to stop servers")
    print("=" * 60)
    
    try:
        # Wait for interrupt
        voice_server.wait()
        web_server.wait()
    except KeyboardInterrupt:
        print("\n\nStopping servers...")
        voice_server.terminate()
        web_server.terminate()
        voice_server.wait()
        web_server.wait()
        print("Servers stopped")
    
    return True

if __name__ == "__main__":
    os.chdir(Path(__file__).parent)
    start_servers()

