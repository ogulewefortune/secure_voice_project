"""
Configuration module.
Handles application configuration and settings.
"""

# Default configuration values
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8888
DEFAULT_WEB_PORT = 5001  # Web server port (5000 often used by macOS AirPlay)
DEFAULT_SAMPLE_RATE = 8000  # Reduced for 64 Kbps requirement
DEFAULT_CHUNK_SIZE = 1024
DEFAULT_AUDIO_FORMAT = "pcm"

# Audio quality requirements
TARGET_BITRATE = 64000  # 64 Kbps requirement
QUANTIZATION_BITS = 8  # 8-bit quantization for 64 Kbps (8000 Hz * 8 bits = 64 Kbps)
MIN_SNR_DB = 40  # Minimum SNR requirement: 40dB
SAMPLE_RATE_FOR_64KBPS = 8000  # Sample rate for 64 Kbps

# Security settings
ENCRYPTION_ALGORITHM = "AES-256"
KEY_EXCHANGE_ALGORITHM = "ECDH"
ENABLE_INTEGRITY_CHECK = True  # Protection against content manipulation

# Network settings
BUFFER_SIZE = 4096
CONNECTION_TIMEOUT = 30

