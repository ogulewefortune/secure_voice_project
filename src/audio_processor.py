"""
Audio processing module.
Handles audio capture, encoding, decoding, and playback.
"""

import pyaudio
import numpy as np
from src.config import DEFAULT_SAMPLE_RATE, DEFAULT_CHUNK_SIZE


class AudioProcessor:
    """Handles audio capture and playback."""
    
    def __init__(self, sample_rate=DEFAULT_SAMPLE_RATE, chunk_size=DEFAULT_CHUNK_SIZE):
        self.sample_rate = sample_rate
        self.chunk_size = chunk_size
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.audio = pyaudio.PyAudio()
        self.input_stream = None
        self.output_stream = None
    
    def start_capture(self):
        """Start capturing audio from microphone."""
        if self.input_stream is None:
            self.input_stream = self.audio.open(
                format=self.audio_format,
                channels=self.channels,
                rate=self.sample_rate,
                input=True,
                frames_per_buffer=self.chunk_size
            )
    
    def stop_capture(self):
        """Stop capturing audio."""
        if self.input_stream:
            self.input_stream.stop_stream()
            self.input_stream.close()
            self.input_stream = None
    
    def start_playback(self):
        """Start audio playback stream."""
        if self.output_stream is None:
            self.output_stream = self.audio.open(
                format=self.audio_format,
                channels=self.channels,
                rate=self.sample_rate,
                output=True,
                frames_per_buffer=self.chunk_size
            )
    
    def stop_playback(self):
        """Stop audio playback."""
        if self.output_stream:
            self.output_stream.stop_stream()
            self.output_stream.close()
            self.output_stream = None
    
    def capture_audio(self):
        """Capture a chunk of audio from microphone."""
        if self.input_stream:
            try:
                data = self.input_stream.read(self.chunk_size, exception_on_overflow=False)
                return data
            except Exception as e:
                print(f"Error capturing audio: {e}")
                return None
        return None
    
    def play_audio(self, audio_data):
        """Play audio data."""
        if self.output_stream and audio_data:
            try:
                self.output_stream.write(audio_data)
            except Exception as e:
                print(f"Error playing audio: {e}")
    
    def cleanup(self):
        """Clean up audio resources."""
        self.stop_capture()
        self.stop_playback()
        self.audio.terminate()


def encode_audio(audio_data):
    """Encode audio data for transmission (base64 encoding for binary data)."""
    import base64
    return base64.b64encode(audio_data)


def decode_audio(encoded_data):
    """Decode audio data from transmission."""
    import base64
    return base64.b64decode(encoded_data)

