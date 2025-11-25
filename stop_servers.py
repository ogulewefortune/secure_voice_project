#!/usr/bin/env python3
"""
Python script to stop both servers.
Run: python3 stop_servers.py
"""

import subprocess
import sys
import time
import os
from pathlib import Path

def stop_servers():
    """Stop both voice server and web server."""
    print("=" * 60)
    print("Stopping Secure Voice Communication Servers")
    print("=" * 60)
    print()
    
    os.chdir(Path(__file__).parent)
    
    # Stop by PID files if they exist
    voice_pid = None
    web_pid = None
    
    if os.path.exists(".voice_server.pid"):
        with open(".voice_server.pid", "r") as f:
            voice_pid = f.read().strip()
        try:
            voice_pid = int(voice_pid)
            if os.path.exists(f"/proc/{voice_pid}") or subprocess.run(
                ["ps", "-p", str(voice_pid)], 
                capture_output=True
            ).returncode == 0:
                print(f"Stopping voice server (PID: {voice_pid})...")
                try:
                    os.kill(voice_pid, 15)  # SIGTERM
                    time.sleep(1)
                    os.kill(voice_pid, 9)  # SIGKILL if still running
                except ProcessLookupError:
                    pass
                print("Voice server stopped")
            else:
                print(f"Voice server was not running (PID: {voice_pid})")
        except (ValueError, ProcessLookupError):
            pass
        os.remove(".voice_server.pid")
    
    if os.path.exists(".web_server.pid"):
        with open(".web_server.pid", "r") as f:
            web_pid = f.read().strip()
        try:
            web_pid = int(web_pid)
            if os.path.exists(f"/proc/{web_pid}") or subprocess.run(
                ["ps", "-p", str(web_pid)], 
                capture_output=True
            ).returncode == 0:
                print(f"Stopping web server (PID: {web_pid})...")
                try:
                    os.kill(web_pid, 15)  # SIGTERM
                    time.sleep(1)
                    os.kill(web_pid, 9)  # SIGKILL if still running
                except ProcessLookupError:
                    pass
                print("Web server stopped")
            else:
                print(f"Web server was not running (PID: {web_pid})")
        except (ValueError, ProcessLookupError):
            pass
        os.remove(".web_server.pid")
    
    # Also try to stop by process name (fallback)
    print()
    print("Checking for any remaining processes...")
    
    # Stop voice server processes
    result = subprocess.run(
        ["pgrep", "-f", "run_server.py"],
        capture_output=True,
        text=True
    )
    if result.stdout.strip():
        print("Found voice server processes, stopping...")
        subprocess.run(["pkill", "-f", "run_server.py"], capture_output=True)
        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "run_server.py"], capture_output=True)
        print("Voice server processes stopped")
    
    # Stop web server processes
    result = subprocess.run(
        ["pgrep", "-f", "run_web_server.py"],
        capture_output=True,
        text=True
    )
    if result.stdout.strip():
        print("Found web server processes, stopping...")
        subprocess.run(["pkill", "-f", "run_web_server.py"], capture_output=True)
        time.sleep(1)
        subprocess.run(["pkill", "-9", "-f", "run_web_server.py"], capture_output=True)
        print("Web server processes stopped")
    
    # Check ports
    import socket
    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0
    
    if check_port(8888):
        print("Port 8888 is still in use")
    else:
        print("Port 8888 is free")
    
    if check_port(5000):
        print("Port 5000 is still in use")
    else:
        print("Port 5000 is free")
    
    print()
    print("=" * 60)
    print("All servers stopped")
    print("=" * 60)

if __name__ == "__main__":
    stop_servers()

