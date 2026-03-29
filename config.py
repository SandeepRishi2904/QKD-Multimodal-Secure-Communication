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
FACE_SIMILARITY_THRESHOLD = 0.45  # ArcFace cosine similarity (0.45 is reliable for live capture)
FACE_EMBEDDING_SIZE = 512

# Fingerprint Configuration
FINGERPRINT_VENDOR_ID = 0x0bca  # Access FM220U L1
FINGERPRINT_PRODUCT_ID = 0x2100
FINGERPRINT_BAUDRATE = 115200
FINGERPRINT_TIMEOUT = 5
FINGERPRINT_SIMULATION = True  # Set to True to simulate fingerprint sensor

# Key Fusion Configuration
HKDF_INFO = b"QKD-Biometric-Fusion-v1"
SALT_SIZE = 32

# Network Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_BACKEND_PORT = 8000
DEFAULT_SENDER_PORT = 8501
DEFAULT_RECEIVER_PORT = 8502
DEFAULT_LOGIN_PORT = 8500  # New: Login page port
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# ── Relay server address ──────────────────────────────────────────────────────
# SENDER  → set to "localhost"  (backend runs on this machine)
# RECEIVER → set to the sender's LAN IP  (e.g. "192.168.1.105")
# Find sender's IP with: ipconfig  →  look for "IPv4 Address" under Wi-Fi
SENDER_BACKEND_IP = "localhost"
SENDER_BACKEND_URL = f"http://{SENDER_BACKEND_IP}:{DEFAULT_BACKEND_PORT}"


# Template paths
SENDER_FACE_TEMPLATE = FACE_DIR / "sender_face_template.pkl"
RECEIVER_FACE_TEMPLATE = FACE_DIR / "receiver_face_template.pkl"
SENDER_FINGERPRINT_TEMPLATE = FINGERPRINT_DIR / "sender_fingerprint_template.pkl"
RECEIVER_FINGERPRINT_TEMPLATE = FINGERPRINT_DIR / "receiver_fingerprint_template.pkl"

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ============================================
# ADMIN AUTHENTICATION CONFIGURATION (NEW)
# ============================================

# Admin credentials - CHANGE THESE IN PRODUCTION!
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # Change this!
ADMIN_SESSION_TIMEOUT = 3600  # 1 hour in seconds

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"

# Admin data storage
ADMIN_DIR = DATA_DIR / "admin"
ADMIN_DIR.mkdir(parents=True, exist_ok=True)
ADMIN_LOG_FILE = ADMIN_DIR / "admin_logs.txt"
ADMIN_SESSIONS_FILE = ADMIN_DIR / "active_sessions.json"