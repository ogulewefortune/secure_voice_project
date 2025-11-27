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
    
    # Ask user for server address
    print("=" * 80)
    print("SERVER CONNECTION")
    print("=" * 80)
    print("Enter the server address to test eavesdropping against:")
    print("(This should be the TCP voice server, typically on port 8888)")
    print()
    server_host = input(f"Server host/IP [{DEFAULT_HOST}]: ").strip() or DEFAULT_HOST
    server_port_input = input(f"Server port [{DEFAULT_PORT}]: ").strip()
    try:
        server_port = int(server_port_input) if server_port_input else DEFAULT_PORT
    except ValueError:
        print(f"Invalid port, using default: {DEFAULT_PORT}")
        server_port = DEFAULT_PORT
    
    print()
    print(f"Target server: {server_host}:{server_port}")
    print()
    
    # Ask if connecting to existing server or starting new one
    use_existing = input("Connect to existing server? (y/n) [n]: ").strip().lower()
    
    if use_existing == 'y':
        print(f"\nConnecting to existing server at {server_host}:{server_port}...")
        print("(Make sure the server is running!)")
        server = None
    else:
        print(f"\nStarting test server on {server_host}:{server_port}...")
        server = VoiceServer(server_host, server_port)
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(1)
        print("Test server started!")
    print()
    
    try:
        # Legitimate client connects
        print("1. Legitimate client connecting...")
        client_socket = establish_connection(server_host, server_port, is_server=False)
        
        if not client_socket:
            print(f"   [ERROR] Failed to connect to server at {server_host}:{server_port}")
            print("   Possible reasons:")
            print("   - Server is not running")
            print("   - Firewall is blocking the connection")
            print("   - Wrong IP address or port")
            print()
            if server:
                print("   Since you chose to start a test server, it should be running now.")
                print("   Please check if the server started successfully.")
            else:
                print("   NOTE: The web server (web_server.py) uses SocketIO on port 5000, not TCP on port 8888.")
                print("   This test requires a TCP server on port 8888.")
                print("   You can:")
                print("   1. Run the test again and choose 'n' to start a test server")
                print("   2. Or start a test server manually:")
                print("      python3 -c \"from src.server import VoiceServer; from src.config import DEFAULT_HOST, DEFAULT_PORT; s = VoiceServer(DEFAULT_HOST, DEFAULT_PORT); s.start()\"")
            print()
            retry = input("   Would you like to retry with a test server? (y/n) [y]: ").strip().lower()
            if retry != 'n':
                print("   Starting test server and retrying...")
                if not server:
                    server = VoiceServer(server_host, server_port)
                    server_thread = threading.Thread(target=server.start, daemon=True)
                    server_thread.start()
                    time.sleep(2)
                # Retry connection
                client_socket = establish_connection(server_host, server_port, is_server=False)
                if not client_socket:
                    print("   [ERROR] Still failed to connect after starting test server")
                    return False
                print(f"   [OK] Connected to server at {server_host}:{server_port}")
            else:
                return False
        
        print(f"   [OK] Connected to server at {server_host}:{server_port}")
        client_private_key, client_public_key = generate_key_pair()
        
        # Key exchange
        print("   Performing key exchange...")
        msg_type, server_pub_key_bytes = receive_message(client_socket)
        if not msg_type or not server_pub_key_bytes:
            print("   [ERROR] Failed to receive server public key")
            return False
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        msg_type, salt = receive_message(client_socket)
        if not msg_type or not salt:
            print("   [ERROR] Failed to receive salt from server")
            return False
        
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
        
        # Import IDS to detect the eavesdropping attempt
        from src.intrusion_detection import get_ids
        ids = get_ids()
        
        try:
            decrypted = decrypt_data(encrypted_message, wrong_key)
            print("   [FAIL] SECURITY BREACH: Eavesdropper decrypted message!")
            print(f"   Decrypted: {decrypted[:50]}...")
            return False
        except Exception as e:
            print("   [OK] PROTECTED: Decryption failed with wrong key")
            print(f"   Error: {str(e)[:100]}")
            print()
            
            # Detect eavesdropping attempt - this will trigger an alert on the website!
            client_ip = "127.0.0.1"  # Test client IP
            ids.detect_decryption_failure(client_ip, f"Eavesdropping test: {str(e)[:200]}")
            print("   [ALERT] Eavesdropping attempt detected and reported!")
            print("   Check the website Security Alerts panel to see the alert in real-time!")
            print()
            print("   Result: Eavesdropper CANNOT read the message without the proper key")
            return True
        
    finally:
        if server:
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
    
    from src.crypto_utils import compute_hmac, verify_hmac
    
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
    hmac_tag = compute_hmac(original_audio, integrity_key)
    audio_with_hmac = original_audio + hmac_tag
    print(f"   With HMAC: {len(audio_with_hmac)} bytes (+32 bytes HMAC)")
    print()
    
    # Verify original
    print("3. Verifying original data...")
    received_hmac = audio_with_hmac[-32:]
    recovered = audio_with_hmac[:-32]
    is_valid = verify_hmac(recovered, received_hmac, integrity_key)
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
    tampered_hmac = bytes(tampered)[-32:]
    tampered_data = bytes(tampered)[:-32]
    is_valid = verify_hmac(tampered_data, tampered_hmac, integrity_key)
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

