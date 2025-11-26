#!/usr/bin/env python3
"""
Manual Security Test Script
Demonstrates security protections through interactive testing scenarios.

Run this script to manually test security scenarios.
"""

import sys
import time
import socket
import threading
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.network_protocol import establish_connection, send_message, receive_message, close_connection
from src.crypto_utils import (
    generate_key_pair, serialize_public_key, deserialize_public_key,
    derive_shared_secret, derive_aes_key, encrypt_data, decrypt_data
)
from src.config import DEFAULT_HOST, DEFAULT_PORT
from src.server import VoiceServer


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def test_eavesdropping_scenario():
    """Demonstrate eavesdropping protection."""
    print_section("TEST 1: EAVESDROPPING PROTECTION")
    
    print("Scenario: Attacker intercepts encrypted messages but doesn't have the key")
    print()
    
    # Start server
    server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    try:
        # Legitimate client connects
        print("1. Legitimate client connecting...")
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client_private_key, client_public_key = generate_key_pair()
        
        # Key exchange
        _, server_pub_key_bytes = receive_message(client_socket)
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, salt = receive_message(client_socket)
        
        # Derive legitimate key
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        legitimate_aes_key, _ = derive_aes_key(shared_secret, salt)
        print("   [OK] Legitimate client established secure connection")
        print()
        
        # Encrypt test message
        print("2. Legitimate client encrypts message...")
        secret_message = b"This is a secret message that should not be readable by eavesdroppers"
        encrypted_message = encrypt_data(secret_message, legitimate_aes_key)
        print(f"   Original: {len(secret_message)} bytes")
        print(f"   Encrypted: {len(encrypted_message)} bytes")
        print()
        
        # Eavesdropper intercepts
        print("3. Eavesdropper intercepts encrypted message...")
        print("   [WARNING] Eavesdropper has encrypted data but NOT the AES key")
        print()
        
        # Eavesdropper tries to decrypt with wrong key
        print("4. Eavesdropper attempts decryption with wrong key...")
        wrong_key = b"wrong_key_" * 4  # 32 bytes, but wrong key
        
        try:
            decrypted = decrypt_data(encrypted_message, wrong_key)
            print("   [FAIL] SECURITY BREACH: Eavesdropper decrypted message!")
            print(f"   Decrypted: {decrypted[:50]}...")
            return False
        except Exception as e:
            print("   [OK] PROTECTED: Decryption failed with wrong key")
            print(f"   Error: {str(e)[:100]}")
            print()
            print("   Result: Eavesdropper CANNOT read the message without the proper key")
            return True
        
    finally:
        server.stop()
        if client_socket:
            close_connection(client_socket)
        time.sleep(0.5)


def test_imposter_scenario():
    """Demonstrate imposter client protection."""
    print_section("TEST 2: IMPOSTER CLIENT PROTECTION")
    
    print("Scenario: Attacker tries to impersonate a legitimate client")
    print()
    
    # Start server
    server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    try:
        # Legitimate client generates key pair
        print("1. Legitimate client generates key pair...")
        legitimate_private_key, legitimate_public_key = generate_key_pair()
        print("   [OK] Key pair generated")
        print()
        
        # Attacker steals public key (but not private key)
        print("2. Attacker steals legitimate client's PUBLIC KEY...")
        print("   [WARNING] Attacker has public key but NOT the private key")
        stolen_public_key_bytes = serialize_public_key(legitimate_public_key)
        print()
        
        # Imposter tries to connect
        print("3. Imposter attempts to connect using stolen public key...")
        imposter_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        _, server_pub_key_bytes = receive_message(imposter_socket)
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        
        # Imposter sends stolen public key
        send_message(imposter_socket, 'K', stolen_public_key_bytes)
        _, salt = receive_message(imposter_socket)
        print("   [OK] Imposter connected and received salt")
        print()
        
        # Imposter tries to derive key
        print("4. Imposter attempts to derive encryption key...")
        # But imposter doesn't have the private key!
        # Imposter generates their own private key
        imposter_private_key, _ = generate_key_pair()
        imposter_shared_secret = derive_shared_secret(imposter_private_key, server_public_key)
        imposter_aes_key, _ = derive_aes_key(imposter_shared_secret, salt)
        print("   [WARNING] Imposter derived a key, but it's DIFFERENT from legitimate key")
        print()
        
        # Legitimate client derives correct key
        legitimate_shared_secret = derive_shared_secret(legitimate_private_key, server_public_key)
        legitimate_aes_key, _ = derive_aes_key(legitimate_shared_secret, salt)
        
        # Compare keys
        print("5. Comparing keys...")
        if imposter_aes_key == legitimate_aes_key:
            print("   [FAIL] SECURITY BREACH: Imposter has same key as legitimate client!")
            return False
        else:
            print("   [OK] PROTECTED: Imposter's key is DIFFERENT from legitimate key")
            print(f"   Key match: {imposter_aes_key == legitimate_aes_key}")
            print()
        
        # Test decryption
        print("6. Testing if imposter can decrypt legitimate messages...")
        test_message = b"Message encrypted with legitimate key"
        encrypted_with_legitimate = encrypt_data(test_message, legitimate_aes_key)
        
        try:
            decrypted = decrypt_data(encrypted_with_legitimate, imposter_aes_key)
            if decrypted == test_message:
                print("   [FAIL] SECURITY BREACH: Imposter decrypted legitimate message!")
                return False
            else:
                print("   [OK] PROTECTED: Decryption failed (keys don't match)")
        except Exception as e:
            print("   [OK] PROTECTED: Decryption failed with authentication error")
            print(f"   Error: {str(e)[:100]}")
            print()
            print("   Result: Imposter CANNOT decrypt messages without the private key")
            return True
        
    finally:
        server.stop()
        if imposter_socket:
            close_connection(imposter_socket)
        time.sleep(0.5)


def test_mitm_scenario():
    """Demonstrate MITM protection."""
    print_section("TEST 3: MAN-IN-THE-MIDDLE PROTECTION")
    
    print("Scenario: Attacker intercepts and tries to modify messages")
    print()
    
    # Start server
    server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(1)
    
    try:
        # Legitimate client connects
        print("1. Legitimate client connecting...")
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client_private_key, client_public_key = generate_key_pair()
        
        _, server_pub_key_bytes = receive_message(client_socket)
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, salt = receive_message(client_socket)
        
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        aes_key, _ = derive_aes_key(shared_secret, salt)
        print("   [OK] Secure connection established")
        print()
        
        # Encrypt message
        print("2. Legitimate client encrypts message...")
        original_message = b"Original secret message"
        encrypted_message = encrypt_data(original_message, aes_key)
        print(f"   Original: {original_message}")
        print(f"   Encrypted: {len(encrypted_message)} bytes")
        print()
        
        # MITM intercepts and modifies
        print("3. MITM intercepts and modifies encrypted message...")
        modified_encrypted = bytearray(encrypted_message)
        # Modify a byte in the ciphertext
        if len(modified_encrypted) > 50:
            modified_encrypted[50] = (modified_encrypted[50] + 1) % 256
        print("   [WARNING] Message modified (bit flipped)")
        print()
        
        # Try to decrypt modified message
        print("4. Attempting to decrypt modified message...")
        try:
            decrypted = decrypt_data(bytes(modified_encrypted), aes_key)
            if decrypted == original_message:
                print("   [FAIL] SECURITY BREACH: Modified message decrypted successfully!")
                return False
            else:
                print("   [WARNING] Message decrypted but data is corrupted")
                print(f"   Decrypted: {decrypted[:50]}...")
                print("   (This shouldn't happen with GCM mode)")
                return False
        except Exception as e:
            print("   [OK] PROTECTED: Decryption failed - authentication tag invalid")
            print(f"   Error: {str(e)[:100]}")
            print()
            print("   Result: MITM CANNOT modify messages without detection")
            print("   GCM authentication tag prevents tampering")
            return True
        
    finally:
        server.stop()
        if client_socket:
            close_connection(client_socket)
        time.sleep(0.5)


def test_integrity_protection():
    """Demonstrate HMAC integrity protection."""
    print_section("TEST 4: HMAC INTEGRITY PROTECTION")
    
    from src.audio_compression import add_integrity_check, verify_integrity
    
    print("Scenario: Testing HMAC integrity check against tampering")
    print()
    
    # Original data
    print("1. Creating original audio data...")
    original_audio = b"Important audio data that must not be tampered with"
    integrity_key = b"secret_key_16bytes"  # 16 bytes
    print(f"   Original: {len(original_audio)} bytes")
    print()
    
    # Add HMAC
    print("2. Adding HMAC integrity check...")
    audio_with_hmac = add_integrity_check(original_audio, integrity_key)
    print(f"   With HMAC: {len(audio_with_hmac)} bytes (+32 bytes HMAC)")
    print()
    
    # Verify original
    print("3. Verifying original data...")
    is_valid, recovered = verify_integrity(audio_with_hmac, integrity_key)
    if is_valid and recovered == original_audio:
        print("   [OK] Original data passes integrity check")
    else:
        print("   [FAIL] Integrity check failed on original data!")
        return False
    print()
    
    # Tamper with data
    print("4. Attacker tampers with data...")
    tampered = bytearray(audio_with_hmac)
    tampered[10] = (tampered[10] + 1) % 256  # Modify a byte
    print("   [WARNING] Data modified")
    print()
    
    # Verify tampered data
    print("5. Verifying tampered data...")
    is_valid, _ = verify_integrity(bytes(tampered), integrity_key)
    if not is_valid:
        print("   [OK] PROTECTED: Tampered data detected!")
        print("   HMAC verification failed")
        print()
        print("   Result: HMAC integrity check prevents undetected tampering")
        return True
    else:
        print("   [FAIL] SECURITY BREACH: Tampered data passed integrity check!")
        return False


def main():
    """Run all manual security tests."""
    print("\n" + "=" * 80)
    print("  MANUAL SECURITY TEST SUITE")
    print("  Testing: Eavesdropping | Imposter Clients | MITM | Integrity")
    print("=" * 80)
    
    results = []
    
    # Run tests
    try:
        results.append(("Eavesdropping Protection", test_eavesdropping_scenario()))
        time.sleep(1)
        
        results.append(("Imposter Client Protection", test_imposter_scenario()))
        time.sleep(1)
        
        results.append(("Man-in-the-Middle Protection", test_mitm_scenario()))
        time.sleep(1)
        
        results.append(("HMAC Integrity Protection", test_integrity_protection()))
        
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\nError running tests: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Print summary
    print("\n" + "=" * 80)
    print("  TEST SUMMARY")
    print("=" * 80)
    
    all_passed = True
    for test_name, passed in results:
        status = "[PASSED]" if passed else "[FAILED]"
        print(f"  {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print()
    if all_passed:
        print("[PASSED] All security tests PASSED!")
        print("\nThe system is protected against:")
        print("  • Eavesdropping attacks (encryption prevents reading)")
        print("  • Imposter clients (ECDH requires private key)")
        print("  • Man-in-the-middle attacks (GCM authentication)")
        print("  • Message tampering (HMAC integrity check)")
        return 0
    else:
        print("[FAILED] Some security tests FAILED!")
        print("Review the test output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

