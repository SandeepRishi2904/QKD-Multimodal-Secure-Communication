"""
QKD Multimodal Secure Communication System - Configuration
"""
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.absolute()
DATA_DIR = BASE_DIR / "data"
FACE_DIR = DATA_DIR / "faces"
FINGERPRINT_DIR = DATA_DIR / "fingerprints"
KEY_DIR = DATA_DIR / "keys"
TEMP_DIR = DATA_DIR / "temp"

# Ensure directories exist
for dir_path in [DATA_DIR, FACE_DIR, FINGERPRINT_DIR, KEY_DIR, TEMP_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# Security Configuration
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits for GCM
AES_TAG_SIZE = 16  # 128 bits

# BB84 Configuration
BB84_KEY_LENGTH = 256  # bits
BB84_ERROR_THRESHOLD = 0.15  # 15% error threshold for eavesdropping detection

# Face Recognition Configuration
FACE_MODEL = "ArcFace"
FACE_DETECTOR = "opencv"
FACE_SIMILARITY_THRESHOLD = 0.6
FACE_EMBEDDING_SIZE = 512

# Fingerprint Configuration
FINGERPRINT_VENDOR_ID = 0x0bca  # Access FM220U L1
FINGERPRINT_PRODUCT_ID = 0x2100
FINGERPRINT_BAUDRATE = 115200
FINGERPRINT_TIMEOUT = 5

# Key Fusion Configuration
HKDF_INFO = b"QKD-Biometric-Fusion-v1"
SALT_SIZE = 32

# Network Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_BACKEND_PORT = 8000
DEFAULT_SENDER_PORT = 8501
DEFAULT_RECEIVER_PORT = 8502
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Template paths
SENDER_FACE_TEMPLATE = FACE_DIR / "sender_face_template.pkl"
RECEIVER_FACE_TEMPLATE = FACE_DIR / "receiver_face_template.pkl"
SENDER_FINGERPRINT_TEMPLATE = FINGERPRINT_DIR / "sender_fingerprint_template.pkl"
RECEIVER_FINGERPRINT_TEMPLATE = FINGERPRINT_DIR / "receiver_fingerprint_template.pkl"

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
