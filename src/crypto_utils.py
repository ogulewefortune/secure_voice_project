"""
Cryptographic utilities module.
Handles encryption, decryption, key exchange, and secure communication.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64


def generate_key_pair():
    """Generate a public/private key pair using ECDH."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize a public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key_bytes):
    """Deserialize a public key from bytes."""
    return serialization.load_pem_public_key(public_key_bytes, default_backend())


def derive_shared_secret(private_key, peer_public_key):
    """Derive a shared secret using ECDH."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret


def derive_aes_key(shared_secret, salt=None):
    """Derive an AES-256 key from a shared secret."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(shared_secret)
    return key, salt


def encrypt_data(data, key):
    """Encrypt data using AES-256-GCM."""
    iv = os.urandom(12)  # 96-bit IV for GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256-GCM."""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def exchange_keys():
    """Perform secure key exchange."""
    # This is a placeholder - actual key exchange happens during connection
    pass

