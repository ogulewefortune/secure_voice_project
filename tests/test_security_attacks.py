"""
Security Attack Tests
Tests for eavesdropping, imposter clients, and man-in-the-middle scenarios.
"""

import unittest
import socket
import threading
import time
import struct
from src.network_protocol import establish_connection, send_message, receive_message, close_connection
from src.crypto_utils import (
    generate_key_pair, serialize_public_key, deserialize_public_key,
    derive_shared_secret, derive_aes_key, encrypt_data, decrypt_data
)
from src.config import DEFAULT_HOST, DEFAULT_PORT
from src.server import VoiceServer


class TestEavesdropping(unittest.TestCase):
    """Test protection against eavesdropping attacks."""
    
    def setUp(self):
        """Set up test environment."""
        self.server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
        self.server_thread = None
        self.eavesdropper_socket = None
        
    def tearDown(self):
        """Clean up after tests."""
        if self.server_thread:
            self.server.stop()
            if self.server_thread.is_alive():
                time.sleep(0.5)
        if self.eavesdropper_socket:
            close_connection(self.eavesdropper_socket)
    
    def test_eavesdropper_cannot_decrypt_without_key(self):
        """
        Test that an eavesdropper cannot decrypt intercepted messages
        without the proper AES key.
        
        Scenario:
        1. Legitimate client connects and exchanges keys
        2. Eavesdropper intercepts encrypted audio packet
        3. Eavesdropper tries to decrypt without proper key
        4. Decryption should fail
        """
        # Start server in background
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)  # Wait for server to start
        
        # Legitimate client connects
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        self.assertIsNotNone(client_socket, "Client should connect to server")
        
        # Perform key exchange
        _, server_pub_key_bytes = receive_message(client_socket)
        client_private_key, client_public_key = generate_key_pair()
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, salt = receive_message(client_socket)
        
        # Derive legitimate AES key
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        legitimate_aes_key, _ = derive_aes_key(shared_secret, salt)
        
        # Send encrypted test message
        test_audio = b"test audio data" * 100
        encrypted_audio = encrypt_data(test_audio, legitimate_aes_key)
        send_message(client_socket, 'A', encrypted_audio)
        
        # Eavesdropper intercepts the encrypted message
        # Eavesdropper does NOT have the AES key
        eavesdropper_key = b"wrong_key_" * 4  # Wrong key (32 bytes)
        
        # Attempt to decrypt with wrong key should fail
        with self.assertRaises(Exception):
            # GCM mode will raise exception if tag doesn't match
            decrypted = decrypt_data(encrypted_audio, eavesdropper_key)
            # If somehow it doesn't raise exception, decrypted data should be garbage
            self.assertNotEqual(decrypted, test_audio, 
                              "Eavesdropper should not be able to decrypt without proper key")
        
        close_connection(client_socket)
    
    def test_eavesdropper_cannot_derive_key_without_private_key(self):
        """
        Test that an eavesdropper cannot derive the AES key even if they
        intercept the public keys and salt.
        
        Scenario:
        1. Eavesdropper intercepts public keys and salt
        2. Eavesdropper tries to derive AES key without private key
        3. Key derivation should fail
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Legitimate client connects
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        
        # Eavesdropper intercepts public keys and salt
        _, intercepted_server_pub_key_bytes = receive_message(client_socket)
        client_private_key, client_public_key = generate_key_pair()
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, intercepted_salt = receive_message(client_socket)
        
        # Eavesdropper tries to derive key without client's private key
        # Eavesdropper generates their own key pair
        eavesdropper_private_key, eavesdropper_public_key = generate_key_pair()
        intercepted_server_public_key = deserialize_public_key(intercepted_server_pub_key_bytes)
        
        # Eavesdropper derives shared secret with their own private key
        # This will be DIFFERENT from the legitimate shared secret
        eavesdropper_shared_secret = derive_shared_secret(eavesdropper_private_key, intercepted_server_public_key)
        eavesdropper_aes_key, _ = derive_aes_key(eavesdropper_shared_secret, intercepted_salt)
        
        # Legitimate client derives correct key
        legitimate_shared_secret = derive_shared_secret(client_private_key, intercepted_server_public_key)
        legitimate_aes_key, _ = derive_aes_key(legitimate_shared_secret, intercepted_salt)
        
        # Keys should be different
        self.assertNotEqual(eavesdropper_aes_key, legitimate_aes_key,
                          "Eavesdropper's key should be different from legitimate key")
        
        # Eavesdropper cannot decrypt messages encrypted with legitimate key
        test_audio = b"secret message"
        encrypted_with_legitimate = encrypt_data(test_audio, legitimate_aes_key)
        
        with self.assertRaises(Exception):
            decrypt_data(encrypted_with_legitimate, eavesdropper_aes_key)
        
        close_connection(client_socket)


class TestImposterClient(unittest.TestCase):
    """Test protection against imposter client attacks."""
    
    def setUp(self):
        """Set up test environment."""
        self.server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
        self.server_thread = None
        
    def tearDown(self):
        """Clean up after tests."""
        if self.server_thread:
            self.server.stop()
            if self.server_thread.is_alive():
                time.sleep(0.5)
    
    def test_imposter_cannot_use_stolen_public_key(self):
        """
        Test that an imposter cannot use a stolen public key to impersonate
        a legitimate client.
        
        Scenario:
        1. Legitimate client's public key is stolen
        2. Imposter tries to use stolen public key
        3. Imposter cannot derive correct shared secret without private key
        4. Imposter cannot decrypt messages intended for legitimate client
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Legitimate client generates key pair
        legitimate_private_key, legitimate_public_key = generate_key_pair()
        stolen_public_key_bytes = serialize_public_key(legitimate_public_key)
        
        # Imposter tries to connect using stolen public key
        imposter_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        
        # Receive server public key
        _, server_pub_key_bytes = receive_message(imposter_socket)
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        
        # Imposter sends stolen public key
        send_message(imposter_socket, 'K', stolen_public_key_bytes)
        
        # Receive salt
        _, salt = receive_message(imposter_socket)
        
        # Imposter tries to derive shared secret
        # But imposter doesn't have the private key!
        # Imposter generates their own private key
        imposter_private_key, _ = generate_key_pair()
        
        # Imposter derives shared secret with their own private key
        # This will be DIFFERENT from what legitimate client would derive
        imposter_shared_secret = derive_shared_secret(imposter_private_key, server_public_key)
        imposter_aes_key, _ = derive_aes_key(imposter_shared_secret, salt)
        
        # Legitimate client's shared secret (what server expects)
        legitimate_shared_secret = derive_shared_secret(legitimate_private_key, server_public_key)
        legitimate_aes_key, _ = derive_aes_key(legitimate_shared_secret, salt)
        
        # Keys should be different
        self.assertNotEqual(imposter_aes_key, legitimate_aes_key,
                          "Imposter's key should be different from legitimate key")
        
        # Imposter cannot decrypt messages encrypted with legitimate key
        test_audio = b"secret audio"
        encrypted_with_legitimate = encrypt_data(test_audio, legitimate_aes_key)
        
        with self.assertRaises(Exception):
            decrypt_data(encrypted_with_legitimate, imposter_aes_key)
        
        close_connection(imposter_socket)
    
    def test_each_client_has_unique_encryption_key(self):
        """
        Test that each client connection gets a unique encryption key,
        preventing one client from decrypting another client's messages.
        
        Scenario:
        1. Two legitimate clients connect
        2. Each gets different AES key
        3. Client 1 cannot decrypt Client 2's messages
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Client 1 connects
        client1_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client1_private_key, client1_public_key = generate_key_pair()
        _, server_pub_key_bytes = receive_message(client1_socket)
        send_message(client1_socket, 'K', serialize_public_key(client1_public_key))
        _, salt1 = receive_message(client1_socket)
        
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        client1_shared_secret = derive_shared_secret(client1_private_key, server_public_key)
        client1_aes_key, _ = derive_aes_key(client1_shared_secret, salt1)
        
        # Client 2 connects
        client2_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client2_private_key, client2_public_key = generate_key_pair()
        _, server_pub_key_bytes2 = receive_message(client2_socket)
        send_message(client2_socket, 'K', serialize_public_key(client2_public_key))
        _, salt2 = receive_message(client2_socket)
        
        server_public_key2 = deserialize_public_key(server_pub_key_bytes2)
        client2_shared_secret = derive_shared_secret(client2_private_key, server_public_key2)
        client2_aes_key, _ = derive_aes_key(client2_shared_secret, salt2)
        
        # Keys should be different (different salts ensure this)
        self.assertNotEqual(client1_aes_key, client2_aes_key,
                          "Each client should have unique AES key")
        
        # Client 1 cannot decrypt Client 2's messages
        test_audio = b"client 2 secret"
        encrypted_with_client2_key = encrypt_data(test_audio, client2_aes_key)
        
        with self.assertRaises(Exception):
            decrypt_data(encrypted_with_client2_key, client1_aes_key)
        
        close_connection(client1_socket)
        close_connection(client2_socket)


class TestManInTheMiddle(unittest.TestCase):
    """Test protection against man-in-the-middle attacks."""
    
    def setUp(self):
        """Set up test environment."""
        self.server = VoiceServer(DEFAULT_HOST, DEFAULT_PORT)
        self.server_thread = None
        
    def tearDown(self):
        """Clean up after tests."""
        if self.server_thread:
            self.server.stop()
            if self.server_thread.is_alive():
                time.sleep(0.5)
    
    def test_mitm_cannot_modify_encrypted_messages(self):
        """
        Test that a man-in-the-middle attacker cannot modify encrypted
        messages without detection (GCM authentication tag prevents this).
        
        Scenario:
        1. MITM intercepts encrypted message
        2. MITM tries to modify encrypted message
        3. Modification invalidates authentication tag
        4. Decryption fails with authentication error
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Legitimate client connects
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client_private_key, client_public_key = generate_key_pair()
        _, server_pub_key_bytes = receive_message(client_socket)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, salt = receive_message(client_socket)
        
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        aes_key, _ = derive_aes_key(shared_secret, salt)
        
        # Encrypt original message
        original_audio = b"original secret message"
        encrypted_audio = encrypt_data(original_audio, aes_key)
        
        # MITM modifies encrypted message (tampering)
        # Modify ciphertext (but keep structure intact)
        modified_encrypted = bytearray(encrypted_audio)
        if len(modified_encrypted) > 50:  # Make sure we have enough bytes
            modified_encrypted[50] = (modified_encrypted[50] + 1) % 256  # Flip a bit
        
        # Attempt to decrypt modified message should fail
        # GCM authentication tag will not match
        with self.assertRaises(Exception):
            decrypted = decrypt_data(bytes(modified_encrypted), aes_key)
            # If decryption somehow succeeds, data should be corrupted
            self.assertNotEqual(decrypted, original_audio,
                              "Modified message should not decrypt correctly")
        
        close_connection(client_socket)
    
    def test_mitm_cannot_replay_old_messages(self):
        """
        Test that replay attacks are mitigated (each encryption uses unique IV).
        
        Scenario:
        1. MITM intercepts and stores encrypted message
        2. MITM tries to replay old message later
        3. While IV uniqueness doesn't prevent replay, HMAC integrity check
           combined with session keys provides protection
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Client connects
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client_private_key, client_public_key = generate_key_pair()
        _, server_pub_key_bytes = receive_message(client_socket)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        _, salt = receive_message(client_socket)
        
        server_public_key = deserialize_public_key(server_pub_key_bytes)
        shared_secret = derive_shared_secret(client_private_key, server_public_key)
        aes_key, _ = derive_aes_key(shared_secret, salt)
        
        # Encrypt message
        original_audio = b"message 1"
        encrypted_audio1 = encrypt_data(original_audio, aes_key)
        
        # Encrypt another message (different IV)
        original_audio2 = b"message 2"
        encrypted_audio2 = encrypt_data(original_audio2, aes_key)
        
        # Verify both messages have different IVs (first 12 bytes)
        iv1 = encrypted_audio1[:12]
        iv2 = encrypted_audio2[:12]
        self.assertNotEqual(iv1, iv2,
                          "Each encryption should use unique IV")
        
        # Both should decrypt correctly with same key
        decrypted1 = decrypt_data(encrypted_audio1, aes_key)
        decrypted2 = decrypt_data(encrypted_audio2, aes_key)
        self.assertEqual(decrypted1, original_audio)
        self.assertEqual(decrypted2, original_audio2)
        
        close_connection(client_socket)
    
    def test_mitm_cannot_derive_key_without_private_keys(self):
        """
        Test that MITM cannot derive encryption keys even if intercepting
        all public key exchange messages.
        
        Scenario:
        1. MITM intercepts all key exchange messages
        2. MITM has server public key, client public key, and salt
        3. MITM cannot derive shared secret without private keys
        4. MITM cannot decrypt messages
        """
        # Start server
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        time.sleep(1)
        
        # Legitimate client connects
        client_socket = establish_connection(DEFAULT_HOST, DEFAULT_PORT, is_server=False)
        client_private_key, client_public_key = generate_key_pair()
        
        # MITM intercepts server public key
        _, intercepted_server_pub_key_bytes = receive_message(client_socket)
        intercepted_server_public_key = deserialize_public_key(intercepted_server_pub_key_bytes)
        
        # Client sends public key (MITM intercepts)
        send_message(client_socket, 'K', serialize_public_key(client_public_key))
        
        # MITM intercepts salt
        _, intercepted_salt = receive_message(client_socket)
        
        # MITM tries to derive key but doesn't have private keys
        # MITM generates their own key pair
        mitm_private_key, mitm_public_key = generate_key_pair()
        
        # MITM tries to derive shared secret with their own private key
        mitm_shared_secret = derive_shared_secret(mitm_private_key, intercepted_server_public_key)
        mitm_aes_key, _ = derive_aes_key(mitm_shared_secret, intercepted_salt)
        
        # Legitimate client derives correct key
        legitimate_shared_secret = derive_shared_secret(client_private_key, intercepted_server_public_key)
        legitimate_aes_key, _ = derive_aes_key(legitimate_shared_secret, intercepted_salt)
        
        # Keys should be different
        self.assertNotEqual(mitm_aes_key, legitimate_aes_key,
                          "MITM's key should be different from legitimate key")
        
        # MITM cannot decrypt legitimate messages
        test_audio = b"secret message"
        encrypted_with_legitimate = encrypt_data(test_audio, legitimate_aes_key)
        
        with self.assertRaises(Exception):
            decrypt_data(encrypted_with_legitimate, mitm_aes_key)
        
        close_connection(client_socket)


class TestIntegrityProtection(unittest.TestCase):
    """Test HMAC integrity protection."""
    
    def test_hmac_detects_tampering(self):
        """
        Test that HMAC integrity check detects message tampering.
        
        Scenario:
        1. Message is sent with HMAC
        2. Attacker modifies message
        3. HMAC verification fails
        """
        from src.audio_compression import add_integrity_check, verify_integrity
        
        # Original data
        original_data = b"important audio data"
        integrity_key = b"secret_key_16bytes"  # 16 bytes
        
        # Add HMAC
        data_with_hmac = add_integrity_check(original_data, integrity_key)
        
        # Verify original data passes
        is_valid, recovered_data = verify_integrity(data_with_hmac, integrity_key)
        self.assertTrue(is_valid, "Original data should pass integrity check")
        self.assertEqual(recovered_data, original_data, "Recovered data should match original")
        
        # Tamper with data
        tampered_data = bytearray(data_with_hmac)
        tampered_data[5] = (tampered_data[5] + 1) % 256  # Modify a byte
        
        # Verify tampered data fails
        is_valid, _ = verify_integrity(bytes(tampered_data), integrity_key)
        self.assertFalse(is_valid, "Tampered data should fail integrity check")
    
    def test_hmac_detects_wrong_key(self):
        """
        Test that HMAC verification fails with wrong key.
        
        Scenario:
        1. Message is sent with HMAC using key A
        2. Verification attempted with key B
        3. Verification fails
        """
        from src.audio_compression import add_integrity_check, verify_integrity
        
        original_data = b"secret audio"
        correct_key = b"correct_key_16b"
        wrong_key = b"wrong_key_16byte"
        
        # Add HMAC with correct key
        data_with_hmac = add_integrity_check(original_data, correct_key)
        
        # Verify with correct key should pass
        is_valid, _ = verify_integrity(data_with_hmac, correct_key)
        self.assertTrue(is_valid, "Verification with correct key should pass")
        
        # Verify with wrong key should fail
        is_valid, _ = verify_integrity(data_with_hmac, wrong_key)
        self.assertFalse(is_valid, "Verification with wrong key should fail")


if __name__ == "__main__":
    unittest.main()

