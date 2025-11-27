"""
Decryption Model for Secure Voice Transmission System

This module provides a model-based approach to audio decryption,
encapsulating all decryption logic in a clean, reusable class.
"""

import base64
import numpy as np
from typing import Optional, Dict, Tuple
from src.crypto_utils import verify_secure_packet
from src.error_correction import ErrorCorrection
from src.audio_processor import AudioProcessor


class DecryptionModel:
    """
    Model for decrypting secure audio packets.
    
    This model handles the complete decryption pipeline:
    1. RSA signature verification
    2. HMAC verification
    3. AES-GCM decryption
    4. Reed-Solomon error correction
    5. ADPCM decompression
    6. Original audio retrieval
    """
    
    def __init__(self, 
                 audio_processor: AudioProcessor,
                 error_correction: ErrorCorrection,
                 original_audio_store: Dict[str, str]):
        """
        Initialize the decryption model.
        
        Args:
            audio_processor: AudioProcessor instance for decompression
            error_correction: ErrorCorrection instance for Reed-Solomon decoding
            original_audio_store: Dictionary mapping message_id to original audio (base64)
        """
        self.audio_processor = audio_processor
        self.error_correction = error_correction
        self.original_audio_store = original_audio_store
    
    def decrypt_audio(self,
                     secure_packet_bytes: bytes,
                     session_key: bytes,
                     hmac_key: bytes,
                     public_key,
                     expected_sequence: int,
                     message_id: Optional[str] = None,
                     associated_data: bytes = b'') -> Dict:
        """
        Decrypt and process a secure audio packet.
        
        Args:
            secure_packet_bytes: The encrypted secure packet (bytes)
            session_key: AES session key for decryption
            hmac_key: HMAC key for integrity verification
            public_key: RSA public key for signature verification
            expected_sequence: Expected sequence number
            message_id: Optional message ID for original audio lookup
            associated_data: Optional associated data for AES-GCM
        
        Returns:
            Dictionary with:
                - 'status': 'success' or 'error'
                - 'audio': Decrypted audio (base64) if successful
                - 'original_size': Size of original audio
                - 'compressed_size': Size of compressed audio
                - 'errors_corrected': Number of errors corrected
                - 'message': Error message if failed
                - 'next_sequence': Next expected sequence number
        """
        try:
            # Step 1: Verify and decrypt secure packet (RSA + HMAC + AES-GCM)
            ec_data, next_sequence = verify_secure_packet(
                secure_packet=secure_packet_bytes,
                session_key=session_key,
                hmac_key=hmac_key,
                public_key=public_key,
                expected_sequence=expected_sequence,
                associated_data=associated_data
            )
            
            # Step 2: Decode Reed-Solomon error correction
            adpcm_data, errors_corrected = self.error_correction.decode(ec_data)
            
            # Step 3: Try to get original audio from store (preferred)
            if message_id and message_id in self.original_audio_store:
                # Use pristine original audio (no quantization artifacts)
                decrypted_audio_base64 = self.original_audio_store[message_id]
                original_audio_bytes = base64.b64decode(decrypted_audio_base64)
                original_size = len(original_audio_bytes)
                compressed_size = len(adpcm_data)
                
                return {
                    'status': 'success',
                    'audio': decrypted_audio_base64,
                    'original_size': original_size,
                    'compressed_size': compressed_size,
                    'errors_corrected': errors_corrected,
                    'next_sequence': next_sequence,
                    'source': 'original_store'  # Indicates we used original audio
                }
            
            # Step 4: Fallback - decompress ADPCM to PCM
            # Estimate number of samples (ADPCM is 4 bits per sample, so 1 byte = 2 samples)
            estimated_samples = len(adpcm_data) * 2
            reconstructed_audio = self.audio_processor.process_for_playback(adpcm_data, estimated_samples)
            
            # Convert to int16 PCM
            pcm_audio = (reconstructed_audio * 32767).astype(np.int16)
            decompressed_pcm_data = pcm_audio.tobytes()
            decompressed_size = len(decompressed_pcm_data)
            
            # Convert to base64 for transmission
            decompressed_audio_base64 = base64.b64encode(decompressed_pcm_data).decode('utf-8')
            
            return {
                'status': 'success',
                'audio': decompressed_audio_base64,
                'original_size': decompressed_size,
                'compressed_size': len(adpcm_data),
                'errors_corrected': errors_corrected,
                'next_sequence': next_sequence,
                'source': 'decompressed'  # Indicates we decompressed from ADPCM
            }
            
        except ValueError as e:
            # Verification or decryption failed
            error_msg = str(e)
            
            # Determine error type
            if "Signature verification failed" in error_msg:
                error_type = 'signature_failed'
            elif "HMAC verification failed" in error_msg:
                error_type = 'hmac_failed'
            elif "Sequence number mismatch" in error_msg:
                error_type = 'sequence_mismatch'
            else:
                error_type = 'decryption_failed'
            
            return {
                'status': 'error',
                'error_type': error_type,
                'message': error_msg,
                'next_sequence': expected_sequence  # Don't advance on error
            }
        
        except Exception as e:
            # Unexpected error
            return {
                'status': 'error',
                'error_type': 'unexpected_error',
                'message': f'Unexpected error during decryption: {str(e)}',
                'next_sequence': expected_sequence
            }
    
    def decrypt_audio_from_base64(self,
                                  secure_packet_base64: str,
                                  session_key: bytes,
                                  hmac_key: bytes,
                                  public_key,
                                  expected_sequence: int,
                                  message_id: Optional[str] = None,
                                  associated_data: bytes = b'') -> Dict:
        """
        Decrypt audio from base64-encoded secure packet.
        
        Convenience method that decodes base64 before calling decrypt_audio.
        
        Args:
            secure_packet_base64: Base64-encoded secure packet
            session_key: AES session key
            hmac_key: HMAC key
            public_key: RSA public key
            expected_sequence: Expected sequence number
            message_id: Optional message ID
            associated_data: Optional associated data
        
        Returns:
            Same as decrypt_audio()
        """
        try:
            secure_packet_bytes = base64.b64decode(secure_packet_base64)
            return self.decrypt_audio(
                secure_packet_bytes=secure_packet_bytes,
                session_key=session_key,
                hmac_key=hmac_key,
                public_key=public_key,
                expected_sequence=expected_sequence,
                message_id=message_id,
                associated_data=associated_data
            )
        except Exception as e:
            return {
                'status': 'error',
                'error_type': 'base64_decode_error',
                'message': f'Failed to decode base64: {str(e)}',
                'next_sequence': expected_sequence
            }
    
    def get_original_audio(self, message_id: str) -> Optional[str]:
        """
        Get original uncompressed audio from store.
        
        Args:
            message_id: Message ID to lookup
        
        Returns:
            Base64-encoded original audio if found, None otherwise
        """
        return self.original_audio_store.get(message_id)
    
    def has_original_audio(self, message_id: str) -> bool:
        """
        Check if original audio exists in store.
        
        Args:
            message_id: Message ID to check
        
        Returns:
            True if original audio exists, False otherwise
        """
        return message_id in self.original_audio_store

