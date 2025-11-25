"""
Network protocol module.
Handles network communication, message framing, and protocol implementation.
"""

import socket
import struct
import json
from src.config import BUFFER_SIZE


def send_message(sock, message_type, data):
    """Send a message over the network with framing.
    
    Message format: [4 bytes: length][1 byte: type][data]
    """
    try:
        # Prepare message
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        elif isinstance(data, dict):
            data_bytes = json.dumps(data).encode('utf-8')
        else:
            data_bytes = data
        
        # Create message: [length: 4 bytes][type: 1 byte][data: variable]
        message_type_byte = message_type.encode('utf-8')[:1] if isinstance(message_type, str) else bytes([message_type])
        if len(message_type_byte) == 0:
            message_type_byte = b'\x00'
        
        full_message = message_type_byte + data_bytes
        length = len(full_message)
        
        # Send length first (4 bytes, big-endian)
        sock.sendall(struct.pack('>I', length))
        # Send message
        sock.sendall(full_message)
        return True
    except Exception as e:
        print(f"Error sending message: {e}")
        return False


def receive_message(sock):
    """Receive a message from the network.
    
    Returns: (message_type, data) or (None, None) on error
    """
    try:
        # Receive length (4 bytes)
        length_data = b''
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                return None, None
            length_data += chunk
        
        length = struct.unpack('>I', length_data)[0]
        
        # Receive message
        message_data = b''
        while len(message_data) < length:
            chunk = sock.recv(min(length - len(message_data), BUFFER_SIZE))
            if not chunk:
                return None, None
            message_data += chunk
        
        # Extract type and data
        message_type = message_data[0:1].decode('utf-8', errors='ignore')
        data = message_data[1:]
        
        return message_type, data
    except Exception as e:
        print(f"Error receiving message: {e}")
        return None, None


def establish_connection(host, port, is_server=False):
    """Establish a network connection.
    
    Returns: socket object or None on error
    """
    try:
        if is_server:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            return sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            return sock
    except Exception as e:
        print(f"Error establishing connection: {e}")
        return None


def close_connection(sock):
    """Close a network connection."""
    try:
        if sock:
            sock.close()
    except Exception as e:
        print(f"Error closing connection: {e}")

