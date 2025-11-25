#!/usr/bin/env python3
"""
Web server launcher script.
"""

from web_server import app, socketio

if __name__ == '__main__':
    from datetime import datetime
    
    def log(message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    log("=" * 60)
    log("Secure Voice Communication - Web Interface")
    log("=" * 60)
    log("Starting web server on http://localhost:5000")
    log("Open your browser and navigate to: http://localhost:5000")
    log("Make sure the voice server is running on port 8888")
    log("(Run 'python3 run_server.py' in another terminal)")
    log("Press Ctrl+C to stop the web server")
    log("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

