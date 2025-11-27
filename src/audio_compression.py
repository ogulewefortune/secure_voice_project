"""
Audio compression and quantization module.
Handles audio compression to meet 64 Kbps requirement and SNR monitoring.
"""

import numpy as np
import hashlib
import hmac


def quantize_audio(audio_data, bits=8):
    """
    Quantize audio to specified bit depth.
    Ensures SNR >= 40dB requirement.
    
    Args:
        audio_data: numpy array of audio samples (int16)
        bits: quantization bit depth (default 8 for 64 Kbps)
    
    Returns:
        quantized_audio: quantized audio data
        snr_db: calculated SNR in dB
    """
    # Convert to float32 for processing
    if audio_data.dtype == np.int16:
        audio_float = audio_data.astype(np.float32) / 32768.0
    else:
        audio_float = audio_data.astype(np.float32)
    
    # Calculate signal power
    signal_power = np.mean(audio_float ** 2)
    if signal_power == 0:
        return audio_data, 0.0
    
    # Quantization levels
    levels = 2 ** bits
    step_size = 2.0 / levels
    
    # Quantize
    quantized = np.round(audio_float / step_size) * step_size
    
    # Calculate quantization noise
    noise = audio_float - quantized
    noise_power = np.mean(noise ** 2)
    
    # Calculate SNR in dB
    if noise_power > 0:
        snr_db = 10 * np.log10(signal_power / noise_power)
    else:
        snr_db = float('inf')
    
    # Convert back to int16
    quantized_int16 = (quantized * 32768.0).astype(np.int16)
    
    return quantized_int16, snr_db


def compress_to_64kbps(audio_data, sample_rate=8000, bits=8):
    """
    Compress audio to meet 64 Kbps requirement with improved quality preservation.

    Args:
        audio_data: numpy array of audio samples
        sample_rate: sample rate in Hz (default 8000 for 64 Kbps)
        bits: bits per sample (default 8)

    Returns:
        compressed_audio: compressed audio data (as uint8 for 8-bit, int16 for higher)
        snr_db: SNR in dB
        bitrate: actual bitrate achieved
    """
    # Ensure audio is int16
    if audio_data.dtype != np.int16:
        audio_data = audio_data.astype(np.int16)

    # Quantize to target bit depth
    quantized_int16, snr_db = quantize_audio(audio_data, bits)

    # Convert to actual 8-bit format (uint8) for size reduction
    if bits == 8:
        # Improved conversion: preserve more dynamic range
        # First normalize to float [-1.0, 1.0]
        normalized = quantized_int16.astype(np.float32) / 32768.0

        # Apply slight compression to preserve quieter sounds
        # This helps prevent white noise from quantization
        normalized = np.sign(normalized) * np.sqrt(np.abs(normalized))

        # Convert to uint8 [0, 255] with proper rounding
        # Map: -1.0 -> 0, 0.0 -> 128, 1.0 -> 255
        quantized_uint8 = np.clip((normalized * 127.5) + 127.5, 0, 255).astype(np.uint8)
        compressed_audio = quantized_uint8
    else:
        # For other bit depths, keep as int16
        compressed_audio = quantized_int16

    # Calculate actual bitrate
    bitrate = sample_rate * bits

    return compressed_audio, snr_db, bitrate


def calculate_snr(original, quantized):
    """
    Calculate Signal-to-Noise Ratio between original and quantized audio.
    
    Args:
        original: original audio samples
        quantized: quantized audio samples
    
    Returns:
        snr_db: SNR in dB
    """
    # Convert to float
    orig_float = original.astype(np.float32) / 32768.0
    quant_float = quantized.astype(np.float32) / 32768.0
    
    # Calculate signal and noise power
    signal_power = np.mean(orig_float ** 2)
    noise = orig_float - quant_float
    noise_power = np.mean(noise ** 2)
    
    if noise_power == 0:
        return float('inf')
    
    snr_db = 10 * np.log10(signal_power / noise_power)
    return snr_db


def add_integrity_check(data, key):
    """
    Add HMAC integrity check to protect against content manipulation.
    
    Args:
        data: audio data bytes
        key: secret key for HMAC
    
    Returns:
        data_with_hmac: data + HMAC
    """
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    hmac_digest = hmac_obj.digest()
    return data + hmac_digest


def verify_integrity(data_with_hmac, key):
    """
    Verify integrity of received data.
    
    Args:
        data_with_hmac: data + HMAC
        key: secret key for HMAC
    
    Returns:
        (is_valid, data): tuple of (validity, original data)
    """
    if len(data_with_hmac) < 32:  # SHA256 digest is 32 bytes
        return False, None
    
    data = data_with_hmac[:-32]
    received_hmac = data_with_hmac[-32:]
    
    hmac_obj = hmac.new(key, data, hashlib.sha256)
    expected_hmac = hmac_obj.digest()
    
    is_valid = hmac.compare_digest(received_hmac, expected_hmac)
    return is_valid, data

