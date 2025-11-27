"""
Audio Processing Module
Handles ADC simulation, filtering, compression, and SNR optimization
"""

import numpy as np
from scipy import signal
from typing import Tuple, Optional
import struct


class AudioProcessor:
    """
    Processes audio signals for secure transmission
    - ADC simulation with 16-bit quantization (SNR ~= 98 dB theoretical, 38-40 dB practical)
    - Anti-aliasing filtering
    - ADPCM compression (4:1 ratio)
    """

    def __init__(self, sample_rate: int = 8000, bits: int = 16):
        """
        Initialize audio processor

        Args:
            sample_rate: Sampling rate in Hz (8000 for voice quality)
            bits: ADC resolution in bits (16-bit for SNR <= 40dB)
        """
        self.sample_rate = sample_rate
        self.bits = bits
        self.max_amplitude = 2 ** (bits - 1) - 1

        # Design anti-aliasing filter (low-pass at 3.4 kHz for voice)
        nyquist = sample_rate / 2
        cutoff = 3400  # Voice bandwidth
        self.sos = signal.butter(8, cutoff / nyquist, btype='low', output='sos')

        # ADPCM state
        self.reset_adpcm_state()

    def reset_adpcm_state(self):
        """Reset ADPCM encoder/decoder state"""
        self.predicted_sample = 0
        self.step_index = 0
        # ADPCM step size table (IMA ADPCM standard)
        self.step_table = [
            7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
            19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
            50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
            130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
            337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
            876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
            2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
            5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
            15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
        ]
        # Index adjustment table
        self.index_table = [
            -1, -1, -1, -1, 2, 4, 6, 8,
            -1, -1, -1, -1, 2, 4, 6, 8
        ]

    def anti_alias_filter(self, audio_data: np.ndarray) -> np.ndarray:
        """
        Apply anti-aliasing filter to prevent spectral folding

        Args:
            audio_data: Input audio samples (normalized float)

        Returns:
            Filtered audio samples
        """
        return signal.sosfilt(self.sos, audio_data)

    def adc_simulate(self, audio_data: np.ndarray) -> np.ndarray:
        """
        Simulate ADC: quantize continuous signal to discrete levels

        Args:
            audio_data: Normalized audio data [-1.0, 1.0]

        Returns:
            Quantized integer samples
        """
        # Clip to prevent overflow
        audio_clipped = np.clip(audio_data, -1.0, 1.0)

        # Quantize to n-bit integers
        quantized = np.round(audio_clipped * self.max_amplitude).astype(np.int16)

        return quantized

    def dac_simulate(self, quantized_data: np.ndarray) -> np.ndarray:
        """
        Simulate DAC: convert discrete levels back to continuous signal

        Args:
            quantized_data: Quantized integer samples

        Returns:
            Normalized audio data [-1.0, 1.0]
        """
        return quantized_data.astype(np.float32) / self.max_amplitude

    def calculate_snr(self, original: np.ndarray, reconstructed: np.ndarray) -> float:
        """
        Calculate Signal-to-Noise Ratio in dB

        Args:
            original: Original signal
            reconstructed: Reconstructed signal

        Returns:
            SNR in decibels
        """
        # Ensure same length
        min_len = min(len(original), len(reconstructed))
        original = original[:min_len]
        reconstructed = reconstructed[:min_len]

        # Calculate noise
        noise = original - reconstructed

        # Calculate power
        signal_power = np.mean(original ** 2)
        noise_power = np.mean(noise ** 2)

        # Avoid division by zero
        if noise_power < 1e-10:
            return 100.0  # Very high SNR

        snr = 10 * np.log10(signal_power / noise_power)
        return snr

    def adpcm_encode(self, pcm_samples: np.ndarray) -> bytes:
        """
        Encode 16-bit PCM to 4-bit ADPCM (4:1 compression)

        Args:
            pcm_samples: Array of 16-bit PCM samples

        Returns:
            ADPCM encoded bytes
        """
        self.reset_adpcm_state()
        adpcm_nibbles = []

        for sample in pcm_samples:
            # Calculate difference
            diff = sample - self.predicted_sample

            # Get current step size
            step = self.step_table[self.step_index]

            # Quantize difference to 4 bits
            nibble = 0
            if diff < 0:
                nibble = 8  # Sign bit
                diff = -diff

            # Quantize magnitude
            quantized_diff = 0
            for i in range(3):
                if diff >= step:
                    nibble |= (1 << (2 - i))
                    diff -= step
                    quantized_diff += step
                step >>= 1

            # Add 1/2 step for better accuracy
            quantized_diff += step

            if nibble & 8:
                quantized_diff = -quantized_diff

            # Update predicted sample
            self.predicted_sample += quantized_diff
            self.predicted_sample = np.clip(self.predicted_sample, -32768, 32767)

            # Update step index
            self.step_index += self.index_table[nibble]
            self.step_index = np.clip(self.step_index, 0, len(self.step_table) - 1)

            adpcm_nibbles.append(nibble)

        # Pack nibbles into bytes
        adpcm_bytes = bytearray()
        for i in range(0, len(adpcm_nibbles), 2):
            byte = (adpcm_nibbles[i] << 4)
            if i + 1 < len(adpcm_nibbles):
                byte |= adpcm_nibbles[i + 1]
            adpcm_bytes.append(byte)

        return bytes(adpcm_bytes)

    def adpcm_decode(self, adpcm_data: bytes, num_samples: int) -> np.ndarray:
        """
        Decode 4-bit ADPCM to 16-bit PCM

        Args:
            adpcm_data: ADPCM encoded bytes
            num_samples: Number of samples to decode

        Returns:
            Decoded PCM samples
        """
        self.reset_adpcm_state()
        pcm_samples = []

        # Unpack nibbles
        nibbles = []
        for byte in adpcm_data:
            nibbles.append((byte >> 4) & 0x0F)
            nibbles.append(byte & 0x0F)

        for i in range(min(num_samples, len(nibbles))):
            nibble = nibbles[i]

            # Get current step size
            step = self.step_table[self.step_index]

            # Reconstruct difference
            diff = 0
            for j in range(3):
                if nibble & (1 << (2 - j)):
                    diff += step
                step >>= 1
            diff += step  # Add 1/2 step

            # Apply sign
            if nibble & 8:
                diff = -diff

            # Update predicted sample
            self.predicted_sample += diff
            self.predicted_sample = np.clip(self.predicted_sample, -32768, 32767)

            pcm_samples.append(self.predicted_sample)

            # Update step index
            self.step_index += self.index_table[nibble]
            self.step_index = np.clip(self.step_index, 0, len(self.step_table) - 1)

        return np.array(pcm_samples, dtype=np.int16)

    def process_for_transmission(self, audio_data: np.ndarray) -> Tuple[bytes, int]:
        """
        Complete processing pipeline: Filter -> ADC -> Compress

        Args:
            audio_data: Normalized audio input [-1.0, 1.0] or int16 array

        Returns:
            Tuple of (compressed_data, num_samples)
        """
        # Convert int16 to normalized if needed
        if audio_data.dtype == np.int16:
            audio_data = audio_data.astype(np.float32) / 32768.0

        # Step 1: Anti-aliasing filter
        filtered = self.anti_alias_filter(audio_data)

        # Step 2: ADC simulation
        quantized = self.adc_simulate(filtered)

        # Step 3: ADPCM compression
        compressed = self.adpcm_encode(quantized)

        return compressed, len(quantized)

    def process_for_playback(self, compressed_data: bytes, num_samples: int) -> np.ndarray:
        """
        Complete reception pipeline: Decompress -> DAC -> Filter

        Args:
            compressed_data: ADPCM compressed data
            num_samples: Number of original samples

        Returns:
            Reconstructed normalized audio [-1.0, 1.0]
        """
        # Step 1: ADPCM decompression
        decompressed = self.adpcm_decode(compressed_data, num_samples)

        # Step 2: DAC simulation
        analog = self.dac_simulate(decompressed)

        # Step 3: Reconstruction filter
        reconstructed = self.anti_alias_filter(analog)

        return reconstructed
