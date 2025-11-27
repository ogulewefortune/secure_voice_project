"""
Audio Playback Model for Secure Voice Transmission System

This module provides a model-based approach to audio playback,
ensuring decrypted audio is properly formatted and playable.
"""

import base64
import numpy as np
from typing import Optional, Dict, Tuple


class AudioPlaybackModel:
    """
    Model for preparing decrypted audio for playback.
    
    This model handles:
    1. Audio format validation
    2. Byte order correction
    3. WAV file generation
    4. Audio quality verification
    """
    
    def __init__(self, sample_rate: int = 8000, bits_per_sample: int = 16, channels: int = 1):
        """
        Initialize the audio playback model.
        
        Args:
            sample_rate: Audio sample rate in Hz (default: 8000)
            bits_per_sample: Bits per sample (default: 16)
            channels: Number of audio channels (default: 1 for mono)
        """
        self.sample_rate = sample_rate
        self.bits_per_sample = bits_per_sample
        self.channels = channels
    
    def prepare_audio_for_playback(self, audio_base64: str) -> Dict:
        """
        Prepare decrypted audio for playback.
        
        Args:
            audio_base64: Base64-encoded audio data (int16 PCM)
        
        Returns:
            Dictionary with:
                - 'status': 'success' or 'error'
                - 'audio_data': Int16Array data if successful
                - 'sample_count': Number of audio samples
                - 'duration': Audio duration in seconds
                - 'wav_base64': Base64-encoded WAV file (optional)
                - 'message': Error message if failed
        """
        try:
            # Decode base64 audio data
            audio_bytes = base64.b64decode(audio_base64)
            audio_size = len(audio_bytes)
            
            # Validate audio size (must be even for int16)
            if audio_size % 2 != 0:
                return {
                    'status': 'error',
                    'message': f'Invalid audio size: {audio_size} bytes (must be even for int16)'
                }
            
            # Convert bytes to int16 array (little-endian)
            # The audio is stored as int16 bytes, so we need to interpret it correctly
            audio_array = np.frombuffer(audio_bytes, dtype=np.int16)
            
            # Ensure little-endian byte order
            if audio_array.dtype.byteorder == '>' or (audio_array.dtype.byteorder == '=' and np.dtype('<i2').byteorder == '<'):
                # Already little-endian or native (assume little-endian)
                int16_data = audio_array.astype('<i2')  # Force little-endian
            else:
                # Big-endian, convert to little-endian
                int16_data = audio_array.byteswap().astype('<i2')
            
            # Validate audio data (check for reasonable range)
            if len(int16_data) == 0:
                return {
                    'status': 'error',
                    'message': 'Empty audio data'
                }
            
            # Check if audio is all zeros (silence)
            if np.all(int16_data == 0):
                return {
                    'status': 'error',
                    'message': 'Audio data is all zeros (silence)'
                }
            
            # Calculate audio statistics
            sample_count = len(int16_data)
            duration = sample_count / self.sample_rate
            
            # Check audio range (should be within int16 range)
            min_val = np.min(int16_data)
            max_val = np.max(int16_data)
            
            if abs(min_val) > 32767 or abs(max_val) > 32767:
                # Clamp values to valid range
                int16_data = np.clip(int16_data, -32767, 32767).astype(np.int16)
            
            # Calculate RMS (root mean square) for volume check
            rms = np.sqrt(np.mean(int16_data.astype(np.float32) ** 2))
            
            return {
                'status': 'success',
                'audio_data': int16_data,
                'sample_count': sample_count,
                'duration': duration,
                'audio_bytes': audio_bytes,
                'min_value': int(min_val),
                'max_value': int(max_val),
                'rms': float(rms),
                'is_silent': rms < 100  # Threshold for silence detection
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error preparing audio for playback: {str(e)}'
            }
    
    def create_wav_file(self, int16_data: np.ndarray) -> bytes:
        """
        Create a WAV file from int16 PCM data.
        
        Args:
            int16_data: Int16 array of audio samples
        
        Returns:
            WAV file as bytes
        """
        # Calculate sizes
        num_samples = len(int16_data)
        data_size = num_samples * self.channels * (self.bits_per_sample // 8)
        file_size = 36 + data_size
        
        # Create WAV header
        wav_header = bytearray(44)
        
        # RIFF header
        wav_header[0:4] = b'RIFF'
        wav_header[4:8] = file_size.to_bytes(4, byteorder='little')
        wav_header[8:12] = b'WAVE'
        
        # fmt chunk
        wav_header[12:16] = b'fmt '
        wav_header[16:20] = (16).to_bytes(4, byteorder='little')  # fmt chunk size
        wav_header[20:22] = (1).to_bytes(2, byteorder='little')  # audio format (PCM)
        wav_header[22:24] = self.channels.to_bytes(2, byteorder='little')
        wav_header[24:28] = self.sample_rate.to_bytes(4, byteorder='little')
        wav_header[28:32] = (self.sample_rate * self.channels * (self.bits_per_sample // 8)).to_bytes(4, byteorder='little')  # byte rate
        wav_header[32:34] = (self.channels * (self.bits_per_sample // 8)).to_bytes(2, byteorder='little')  # block align
        wav_header[34:36] = self.bits_per_sample.to_bytes(2, byteorder='little')
        
        # data chunk
        wav_header[36:40] = b'data'
        wav_header[40:44] = data_size.to_bytes(4, byteorder='little')
        
        # Convert int16 data to bytes (little-endian)
        audio_bytes = int16_data.astype('<i2').tobytes()
        
        # Combine header and audio data
        wav_file = bytes(wav_header) + audio_bytes
        
        return wav_file
    
    def prepare_and_validate(self, audio_base64: str) -> Dict:
        """
        Prepare audio and create WAV file for playback.
        
        Args:
            audio_base64: Base64-encoded audio data
        
        Returns:
            Dictionary with prepared audio and WAV file
        """
        # Prepare audio
        prep_result = self.prepare_audio_for_playback(audio_base64)
        
        if prep_result['status'] != 'success':
            return prep_result
        
        # Create WAV file
        try:
            wav_file = self.create_wav_file(prep_result['audio_data'])
            wav_base64 = base64.b64encode(wav_file).decode('utf-8')
            
            prep_result['wav_base64'] = wav_base64
            prep_result['wav_size'] = len(wav_file)
            
            return prep_result
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Error creating WAV file: {str(e)}'
            }

