#!/usr/bin/env python3
"""
Generate RSA key pairs for secure voice communication.

This script generates RSA-2048 key pairs that can be used for encryption/decryption.
"""

import os
from cryptography.hazmat.primitives import serialization
from src.crypto_utils import generate_rsa_key_pair, serialize_public_key

def save_key_pair(name="client", output_dir="keys"):
    """
    Generate and save RSA key pair.
    
    Args:
        name: Name prefix for key files (e.g., "client", "alice", "bob")
        output_dir: Directory to save keys
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate RSA key pair
    print(f"Generating RSA-2048 key pair for {name}...")
    private_key, public_key = generate_rsa_key_pair()
    
    # Serialize keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password protection
    )
    
    public_key_pem = serialize_public_key(public_key)
    
    # Save private key
    private_key_path = os.path.join(output_dir, f"{name}_private_key.pem")
    with open(private_key_path, 'wb') as f:
        f.write(private_key_pem)
    print(f" Private key saved to: {private_key_path}")
    print(f"     KEEP THIS SECRET! Never share your private key!")
    
    # Save public key
    public_key_path = os.path.join(output_dir, f"{name}_public_key.pem")
    with open(public_key_path, 'wb') as f:
        f.write(public_key_pem)
    print(f" Public key saved to: {public_key_path}")
    print(f"    You can share this public key with others")
    
    return private_key_path, public_key_path

if __name__ == '__main__':
    import sys
    
    print("=" * 70)
    print("RSA Key Pair Generator")
    print("=" * 70)
    print()
    
    # Get name from command line or use default
    name = sys.argv[1] if len(sys.argv) > 1 else "client"
    
    try:
        private_path, public_path = save_key_pair(name)
        
        print()
        print("=" * 70)
        print("Key Generation Complete!")
        print("=" * 70)
        print()
        print(f"Private Key: {private_path}")
        print(f"Public Key:  {public_path}")
        print()
        print("  SECURITY WARNING:")
        print("   - Keep your private key SECRET and secure")
        print("   - Never share your private key with anyone")
        print("   - You can share your public key freely")
        print("   - The private key is used to decrypt messages")
        print("   - The public key is used by others to encrypt for you")
        print()
        
    except Exception as e:
        print(f"❌ Error generating keys: {e}")
        sys.exit(1)

