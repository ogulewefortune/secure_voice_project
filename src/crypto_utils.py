"""
Cryptographic utilities module.
Handles RSA session key exchange, AES-GCM packet encryption/decryption, HMAC, and RSA signatures.
"""

import os
import json
import struct
import time
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hmac
import hashlib


def generate_rsa_key_pair():
    """Generate RSA public/private key pair (2048 bits)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize RSA public key to bytes (PEM format)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_bytes):
    """Deserialize RSA public key from bytes."""
    return serialization.load_pem_public_key(public_key_bytes, default_backend())


def create_session_key_bundle(aes_key: bytes, hmac_key: bytes) -> dict:
    """Create a session key bundle for RSA encryption."""
    return {
        'aes_key': aes_key.hex(),
        'hmac_key': hmac_key.hex(),
        'timestamp': time.time()
    }


def encrypt_session_keys(key_bundle: dict, peer_public_key) -> bytes:
    """
    Encrypt session keys with receiver's RSA public key (PKCS1_OAEP).
    
    RSA-2048 with OAEP can encrypt max 214 bytes. We use a hybrid approach:
    - Encrypt AES key (32 bytes hex = 64 bytes) with RSA
    - Send HMAC key separately (or combine in a way that fits)
    
    Args:
        key_bundle: Dictionary containing aes_key, hmac_key, timestamp
        peer_public_key: Receiver's RSA public key
    
    Returns:
        Encrypted bundle as bytes (format: encrypted_aes_key + hmac_key + timestamp_bytes)
    """
    # Extract keys from bundle
    aes_key_hex = key_bundle['aes_key']  # 64 bytes (32 bytes hex)
    hmac_key_hex = key_bundle['hmac_key']  # 64 bytes (32 bytes hex)
    timestamp = key_bundle['timestamp']
    
    # Encrypt AES key with RSA (64 bytes fits in 214 byte limit)
    aes_key_bytes = bytes.fromhex(aes_key_hex)
    try:
        encrypted_aes = peer_public_key.encrypt(
            aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError as e:
        raise ValueError(f"Encryption failed: {e}")
    
    # Pack: encrypted_aes (256 bytes) + hmac_key (32 bytes) + timestamp (8 bytes)
    hmac_key_bytes = bytes.fromhex(hmac_key_hex)
    timestamp_bytes = struct.pack('!d', timestamp)  # 8 bytes double
    
    # Final bundle: encrypted_aes + hmac_key + timestamp
    bundle = encrypted_aes + hmac_key_bytes + timestamp_bytes
    
    return bundle


def decrypt_session_keys(encrypted_bundle: bytes, private_key) -> dict:
    """
    Decrypt session keys using RSA private key (PKCS1_OAEP).
    
    Args:
        encrypted_bundle: Encrypted key bundle (encrypted_aes + hmac_key + timestamp)
        private_key: Receiver's RSA private key
    
    Returns:
        Dictionary with aes_key, hmac_key, timestamp
    """
    if private_key is None:
        raise ValueError("Private key not loaded")
    
    try:
        # Split bundle: encrypted_aes (256 bytes) + hmac_key (32 bytes) + timestamp (8 bytes)
        if len(encrypted_bundle) < 256 + 32 + 8:
            raise ValueError("Encrypted bundle too short")
        
        encrypted_aes = encrypted_bundle[:256]
        hmac_key_bytes = encrypted_bundle[256:256+32]
        timestamp_bytes = encrypted_bundle[256+32:256+32+8]
        
        # Decrypt AES key using RSA private key
        aes_key_bytes = private_key.decrypt(
            encrypted_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Reconstruct bundle
        timestamp = struct.unpack('!d', timestamp_bytes)[0]
        key_bundle = {
            'aes_key': aes_key_bytes.hex(),
            'hmac_key': hmac_key_bytes.hex(),
            'timestamp': timestamp
        }
        
        return key_bundle
    except Exception as e:
        raise ValueError(f"Error decrypting session keys: {e}")


def generate_session_keys() -> Tuple[bytes, bytes]:
    """Generate random AES-256 key and HMAC key."""
    aes_key = os.urandom(32)  # 256 bits
    hmac_key = os.urandom(32)  # 256 bits
    return aes_key, hmac_key


def encrypt_packet(data: bytes, session_key: bytes, sequence_number: int, associated_data: bytes = b'') -> bytes:
    """
    Encrypt data using AES-256-GCM with packet format: nonce + seq_bytes + ciphertext + tag.
    
    Args:
        data: Plaintext data to encrypt
        session_key: AES-256 session key
        sequence_number: Sequence number for replay protection
        associated_data: Additional authenticated data
    
    Returns:
        Packet format: nonce (16 bytes) + seq_bytes (4 bytes) + ciphertext + tag (16 bytes)
    """
    # Generate random nonce (16 bytes for GCM)
    nonce = os.urandom(16)
    
    # Pack sequence number as 4-byte big-endian
    seq_bytes = struct.pack('!I', sequence_number)
    
    # Build AAD (additional authenticated data)
    full_aad = associated_data + seq_bytes
    
    # Encrypt with AES-GCM
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, data, full_aad)
    
    # Extract tag (last 16 bytes) and ciphertext
    tag = ciphertext[-16:]
    ciphertext_only = ciphertext[:-16]
    
    # Packet format: nonce + seq_bytes + ciphertext + tag
    packet = nonce + seq_bytes + ciphertext_only + tag
    
    return packet


def decrypt_packet(packet: bytes, session_key: bytes, expected_sequence: int, associated_data: bytes = b'') -> Optional[bytes]:
    """
    Decrypt packet using AES-256-GCM.
    
    Args:
        packet: Encrypted packet (nonce + seq_bytes + ciphertext + tag)
        session_key: AES-256 session key
        expected_sequence: Expected sequence number
        associated_data: Additional authenticated data
    
    Returns:
        Decrypted plaintext or None if verification fails
    """
    if session_key is None:
        raise ValueError("Session key not established")
    
    try:
        # Split packet fields
        nonce = packet[:16]          # first 16 bytes
        seq_bytes = packet[16:20]    # next 4 bytes (sequence number)
        ciphertext = packet[20:-16]  # middle (ciphertext)
        tag = packet[-16:]           # last 16 bytes (GCM tag)
        
        # Check sequence number to prevent replays
        seq_num = struct.unpack('!I', seq_bytes)[0]
        if seq_num < expected_sequence:
            raise ValueError(f"Out-of-order packet (expected {expected_sequence}, got {seq_num})")
        
        # Build AAD (additional authenticated data)
        full_aad = associated_data + seq_bytes
        
        # AES-GCM decrypt + verify
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, full_aad)
        
        return plaintext, seq_num + 1  # Return plaintext and next expected sequence
        
    except (ValueError, Exception) as e:
        raise ValueError(f"Decryption/verification failed: {e}")


def compute_hmac(data: bytes, hmac_key: bytes) -> bytes:
    """Compute HMAC-SHA256 of data."""
    return hmac.new(hmac_key, data, hashlib.sha256).digest()


def verify_hmac(data: bytes, received_hmac: bytes, hmac_key: bytes) -> bool:
    """Verify HMAC-SHA256 of data."""
    expected_hmac = compute_hmac(data, hmac_key)
    return hmac.compare_digest(expected_hmac, received_hmac)


def sign_data(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA private key (PSS padding).
    
    Args:
        data: Data to sign
        private_key: RSA private key
    
    Returns:
        Signature (256 bytes for 2048-bit RSA)
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA signature.
    
    Args:
        data: Original data
        signature: RSA signature (256 bytes)
        public_key: RSA public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def create_secure_packet(data: bytes, session_key: bytes, hmac_key: bytes, 
                        private_key, sequence_number: int, associated_data: bytes = b'') -> bytes:
    """
    Create a secure packet with full protection:
    1. Encrypt with AES-GCM (nonce + seq + ciphertext + tag)
    2. Add HMAC
    3. Add RSA signature
    
    Packet format: encrypted_data + hmac_tag + signature
    Where encrypted_data = nonce + seq_bytes + ciphertext + tag
    
    Args:
        data: Plaintext data
        session_key: AES-256 session key
        hmac_key: HMAC key
        private_key: RSA private key for signing
        sequence_number: Sequence number
        associated_data: Additional authenticated data
    
    Returns:
        Secure packet: encrypted_data + hmac_tag (32 bytes) + signature (256 bytes)
    """
    # Step 1: Encrypt with AES-GCM
    encrypted = encrypt_packet(data, session_key, sequence_number, associated_data)
    
    # Step 2: Add HMAC
    hmac_tag = compute_hmac(encrypted, hmac_key)
    
    # Step 3: Sign (encrypted + hmac_tag)
    signature = sign_data(encrypted + hmac_tag, private_key)
    
    # Final packet: encrypted + hmac_tag + signature
    secure_packet = encrypted + hmac_tag + signature
    
    return secure_packet


def verify_secure_packet(secure_packet: bytes, session_key: bytes, hmac_key: bytes,
                         public_key, expected_sequence: int, associated_data: bytes = b'') -> Optional[bytes]:
    """
    Verify and decrypt a secure packet.
    
    Steps:
    1. Split: signature (last 256 bytes), hmac_tag (32 bytes before that), encrypted (rest)
    2. Verify RSA signature
    3. Verify HMAC
    4. Decrypt AES-GCM
    
    Args:
        secure_packet: Secure packet to verify and decrypt
        session_key: AES-256 session key
        hmac_key: HMAC key
        public_key: RSA public key for signature verification
        expected_sequence: Expected sequence number
        associated_data: Additional authenticated data
    
    Returns:
        Decrypted plaintext or None if verification fails
    """
    if len(secure_packet) < 288:  # Need at least encrypted + hmac (32) + signature (256)
        return None
    
    # Step 1: Split the secure packet
    signature = secure_packet[-256:]      # last 256 bytes = RSA signature
    hmac_tag = secure_packet[-288:-256]    # 32 bytes before signature = HMAC
    encrypted = secure_packet[:-288]       # rest = AES-GCM packet
    
    # Step 2: Verify signature (before decrypting)
    if not verify_signature(encrypted + hmac_tag, signature, public_key):
        raise ValueError("Signature verification failed - possible imposter!")
    
    # Step 3: Verify HMAC
    if not verify_hmac(encrypted, hmac_tag, hmac_key):
        raise ValueError("HMAC verification failed - content manipulated!")
    
    # Step 4: Decrypt AES-GCM
    try:
        plaintext, next_sequence = decrypt_packet(encrypted, session_key, expected_sequence, associated_data)
        return plaintext, next_sequence
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")


# Legacy compatibility functions (for test server and gradual migration)
def generate_key_pair():
    """Legacy: Generate RSA key pair (replaces ECDH)."""
    return generate_rsa_key_pair()


def derive_shared_secret(private_key, peer_public_key):
    """
    Legacy compatibility: Simulate ECDH shared secret derivation using RSA.
    For test server compatibility only - production uses RSA session key exchange.
    
    Returns a deterministic "shared secret" based on both keys for testing.
    """
    # For test compatibility, create a deterministic shared secret
    # by hashing both public keys together
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    peer_pem = serialize_public_key(peer_public_key)
    combined = priv_pem + peer_pem
    return hashlib.sha256(combined).digest()


def derive_aes_key(shared_secret, salt=None):
    """
    Legacy compatibility: Derive AES key from shared secret.
    For test server compatibility only.
    
    Returns:
        (aes_key, salt): Tuple of (32-byte AES key, salt)
    """
    if salt is None:
        salt = os.urandom(16)
    
    # Derive AES key using HKDF-like approach
    key_material = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 100000, 32)
    return key_material, salt


def encrypt_data(data, key):
    """Legacy: Simple AES-GCM encryption (for backward compatibility)."""
    iv = os.urandom(12)  # 96-bit IV for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return iv + ciphertext


def decrypt_data(encrypted_data, key):
    """Legacy: Simple AES-GCM decryption (for backward compatibility)."""
    iv = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
