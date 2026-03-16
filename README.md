🔐 QKD Multimodal Secure Communication System

A cutting-edge secure communication platform combining Quantum Key Distribution (BB84), multimodal biometric authentication (Face + Fingerprint), and military-grade AES-256 encryption.

This system integrates quantum-resistant key exchange with real-time identity verification to provide next-generation secure communication over LAN networks.

🌟 Key Features

🔑 BB84 Quantum Key Distribution – Simulated quantum key exchange protocol

👤 Multimodal Biometric Authentication

Face recognition (Deep Learning-based – ArcFace)

Windows Hello fingerprint integration

🔐 Key Fusion Technology – Combines QKD + Face embeddings + Fingerprint token

🛡️ End-to-End Encryption – AES-256-GCM authenticated encryption

⚡ Real-time Identity Verification – Live biometric validation during encryption/decryption

🌐 LAN Communication – Secure file transfer over local network

🏗️ Architecture
┌─────────────────────────────────────────────────────────────┐
│                    SENDER SIDE                               │
├─────────────────────────────────────────────────────────────┤
│  1. Face Recognition (Live) ──────────┐                     │
│  2. Fingerprint Auth (Windows Hello) ─┼──→ Identity Verified│
│  3. BB84 QKD Key Generation          ─┘                     │
│  4. Key Fusion → AES-256 Key                                │
│  5. File Encryption → Encrypted Payload                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (LAN Transfer)
┌─────────────────────────────────────────────────────────────┐
│                   RECEIVER SIDE                              │
├─────────────────────────────────────────────────────────────┤
│  1. Face Recognition (Live) ──────────┐                     │
│  2. Fingerprint Auth (Windows Hello) ─┼──→ Identity Verified│
│  3. BB84 QKD Key Reconstruction      ─┘                     │
│  4. Key Fusion → AES-256 Key                                │
│  5. Payload Decryption → Original File                      │
└─────────────────────────────────────────────────────────────┘
📋 Prerequisites

Python 3.9+

Windows 10/11 (for Windows Hello fingerprint support)

Webcam (for face recognition)

Fingerprint sensor (optional – fallback mock mode available)

🚀 Installation
1️⃣ Clone the Repository
git clone <repository-url>
cd QKD_Multimodal_Secure_Communication
2️⃣ Create Virtual Environment
python -m venv venv

Activate environment:

Windows

venv\Scripts\activate

Mac/Linux

source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Enroll Biometric Templates (One-Time Setup)

Sender Enrollment

python scripts/enroll_sender.py

Receiver Enrollment

python scripts/enroll_receiver.py
🎯 Usage
▶ Start Backend Server
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
▶ Launch Frontend UI

Terminal 1 – Sender

streamlit run frontend/streamlit_app.py -- --mode sender --port 8501

Terminal 2 – Receiver

streamlit run frontend/streamlit_app.py -- --mode receiver --port 8502
🔄 Workflow
🔹 Sender Side

Open http://localhost:8501

Click Authenticate (Face + Fingerprint verification)

Upload file to encrypt

Click Encrypt & Send

Share encrypted payload with receiver

🔹 Receiver Side

Open http://localhost:8502

Click Authenticate

Upload encrypted payload

Click Decrypt File

Download original file

🔒 Security Features
1️⃣ BB84 Quantum Key Distribution

Simulated quantum key exchange

Eavesdropping detection via basis mismatch

Session-based keys (never reused)

2️⃣ Biometric Authentication
👤 Face Recognition

DeepFace (ArcFace model)

Cosine similarity threshold: 0.6

Live verification

🖐 Fingerprint Authentication

Windows Hello integration

Fallback simulation mode for non-Windows systems

3️⃣ Key Fusion Algorithm
AES_Key = HKDF(
    input_material = QKD_Key || Face_Embedding || Fingerprint_Token,
    salt = random_salt,
    info = "QKD-Biometric-Fusion-v1",
    output_length = 32 bytes
)

HKDF-SHA256 based derivation

256-bit AES key

Multi-factor entropy input

4️⃣ Encryption

AES-256-GCM (Authenticated Encryption)

Unique nonce per encryption

Authentication tag ensures integrity verification

📁 Project Structure
QKD_Multimodal_Secure_Communication/
│
├── data/
│   ├── face_templates/
│   │   ├── sender.pkl
│   │   └── receiver.pkl
│   └── logs/
│       └── auth_logs.txt
│
├── backend/
│   ├── main.py
│   ├── qkd/
│   │   └── bb84.py
│   ├── crypto/
│   │   └── aes_crypto.py
│   ├── biometrics/
│   │   ├── face_enroll.py
│   │   ├── face_auth.py
│   │   └── fingerprint_auth.py
│   ├── security/
│   │   └── key_fusion.py
│   └── utils/
│       └── validators.py
│
├── frontend/
│   ├── streamlit_app.py
│   └── ui_helpers.py
│
└── scripts/
    ├── enroll_sender.py
    └── enroll_receiver.py
🧪 Testing
Run Unit Tests
pytest tests/ -v
Test QKD Protocol
python -m backend.qkd.bb84
Test Biometric Enrollment
python scripts/enroll_sender.py --test
🔧 Configuration

Edit backend/config.py:

# Biometric thresholds
FACE_SIMILARITY_THRESHOLD = 0.6
FINGERPRINT_TIMEOUT = 30  # seconds

# QKD parameters
QKD_KEY_LENGTH = 256
BB84_ERROR_THRESHOLD = 0.11

# Encryption
AES_KEY_SIZE = 32  # 256 bits
📊 Performance
Component	Time
Face Recognition	~1–2 sec
Fingerprint Auth	~0.5–1 sec
BB84 Key Generation	~0.1 sec
File Encryption (1MB)	~50 ms
Total Authentication	~3–5 sec
🛡️ Security Considerations
✅ Strengths

Multi-factor authentication (Biometric-based)

Quantum-resistant key derivation

No permanent key storage

Session-based keys

Authenticated encryption (AES-GCM)

⚠️ Limitations

BB84 is simulated (not real quantum hardware)

Face embeddings stored locally (encrypted)

Requires physical biometric presence

🚀 Future Enhancements

Liveness detection for face authentication

Hardware Security Module (HSM) integration

Real quantum key distribution hardware

Multi-device secure sync

Blockchain-based audit logging

👥 Contributors

Sandeep Rishi J B

Rishikesh C

Rithish Anto A

Shivam Kumar M

🆘 Support

For issues and questions:

Create an issue on GitHub

📧 Email: jbsandeeprishi@gmail.com

🙏 Acknowledgments

DeepFace Library (Face Recognition)

Qiskit (Quantum Computing inspiration)

FastAPI & Streamlit communities
"# QKD-Multimodal-Secure-Communication" 
