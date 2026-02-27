🔐 QKD Multimodal Secure Communication System
https://www.python.org/downloads/
https://opensource.org/licenses/MIT




A cutting-edge secure communication platform combining Quantum Key Distribution (BB84), multimodal biometric authentication (Face + Fingerprint), and military-grade AES-256-GCM encryption.
This system integrates quantum-resistant key exchange with real-time identity verification to provide next-generation secure communication over LAN networks.
🌟 Key Features
Table
Copy
Feature	Technology	Security Level
🔑 BB84 Quantum Key Distribution	Simulated quantum protocol	Information-theoretic security
👤 Face Recognition	DeepFace + ArcFace (512-dim)	99.41% LFW accuracy
🖐 Fingerprint Authentication	Hardware/Simulation mode	1:1 template matching
🔐 Key Fusion	HKDF-SHA256	Cryptographic key derivation
🛡️ End-to-End Encryption	AES-256-GCM	Military-grade authenticated encryption
⚡ Real-time Verification	Live biometric capture	Continuous identity validation
🌐 LAN Communication	REST API + WebSocket	Secure local file transfer
🏗️ System Architecture
plain
Copy
┌─────────────────────────────────────────────────────────────────┐
│                        SENDER SIDE                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Face      │    │ Fingerprint │    │    BB84 QKD         │ │
│  │ Recognition │    │   Scanner   │    │   Key Generation    │ │
│  │  (ArcFace)  │    │  (Hardware) │    │  (256-bit key)      │ │
│  └──────┬──────┘    └──────┬──────┘    └──────────┬──────────┘ │
│         │                  │                     │             │
│         └──────────────────┼─────────────────────┘             │
│                            ▼                                  │
│                   ┌─────────────────┐                          │
│                   │  Identity Check │                          │
│                   │  (AND logic)    │                          │
│                   └────────┬────────┘                          │
│                            ▼                                  │
│                   ┌─────────────────┐                          │
│                   │   Key Fusion    │                          │
│                   │  HKDF(QKD||Salt)│                          │
│                   └────────┬────────┘                          │
│                            ▼                                  │
│                   ┌─────────────────┐                          │
│                   │  AES-256-GCM    │                          │
│                   │  File Encrypt   │                          │
│                   └────────┬────────┘                          │
│                            ▼                                  │
│                   ┌─────────────────┐                          │
│                   │ Encrypted File  │                          │
│                   │   (.enc)        │                          │
│                   └────────┬────────┘                          │
└────────────────────────────┼────────────────────────────────────┘
                             │
                             ▼ LAN/Network Transfer
┌────────────────────────────┼────────────────────────────────────┐
│                            ▼ RECEIVER SIDE                       │
├─────────────────────────────────────────────────────────────────┤
│                   ┌─────────────────┐                          │
│                   │ Encrypted File  │                          │
│                   │   (.enc)        │                          │
│                   └────────┬────────┘                          │
│                            ▼                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Face      │    │ Fingerprint │    │    BB84 QKD         │ │
│  │ Recognition │    │   Scanner   │    │   Key Reconstruction│ │
│  │  (ArcFace)  │    │  (Hardware) │    │  (Same 256-bit key) │ │
│  └──────┬──────┘    └──────┬──────┘    └──────────┬──────────┘ │
│         │                  │                     │             │
│         └──────────────────┼─────────────────────┘             │
│                            ▼                                  │
│                   ┌─────────────────┐                          │
│  ┌─────────────┐ │  Identity Check │                          │
│  │   Salt      │ │  (AND logic)    │                          │
│  │  Extracted  │ └────────┬────────┘                          │
│  │  from File  │          │                                    │
│  └──────┬──────┘          ▼                                    │
│         │           ┌─────────────────┐                          │
│         └──────────▶│   Key Fusion    │                          │
│                     │  HKDF(QKD||Salt)│                          │
│                     └────────┬────────┘                          │
│                              ▼                                  │
│                     ┌─────────────────┐                          │
│                     │  AES-256-GCM    │                          │
│                     │  File Decrypt   │                          │
│                     └────────┬────────┘                          │
│                              ▼                                  │
│                     ┌─────────────────┐                          │
│                     │  Original File  │                          │
│                     │  (Recovered)    │                          │
│                     └─────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
📋 Prerequisites
System Requirements
OS: Windows 10/11, Linux, or macOS
Python: 3.9 or higher
RAM: 4GB minimum (8GB recommended for face recognition)
Camera: Webcam (720p minimum, 1080p recommended)
Fingerprint Sensor: Optional (simulation mode available)
Hardware Support
Table
Copy
Component	Supported Devices	Fallback
Face Recognition	Any USB webcam	✅ Always available
Fingerprint	Access FM220U, ZFM-20, R307	✅ Software simulation
🚀 Installation
1️⃣ Clone the Repository
bash
Copy
git clone https://github.com/yourusername/QKD-Multimodal-Secure-Communication.git
cd QKD-Multimodal-Secure-Communication
2️⃣ Create Virtual Environment
bash
Copy
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
3️⃣ Install Dependencies
bash
Copy
pip install -r requirements.txt
Note: DeepFace will download models (~100MB) on first run.
4️⃣ Enroll Biometric Templates (One-Time Setup)
Sender Enrollment
bash
Copy
python scripts/enroll_face_sender.py
python scripts/enroll_fingerprint_sender.py
Receiver Enrollment
bash
Copy
python scripts/enroll_face_receiver.py
python scripts/enroll_fingerprint_receiver.py
🎯 Usage
▶ Start Backend Server
bash
Copy
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
▶ Launch Frontend UI
Terminal 1 – Sender:
bash
Copy
streamlit run frontend/streamlit_app.py -- --mode sender --port 8501
Terminal 2 – Receiver:
bash
Copy
streamlit run frontend/streamlit_app.py -- --mode receiver --port 8502
🔄 Workflow
🔹 Sender Side
Open http://localhost:8501
Click Authenticate (Face + Fingerprint verification)
Upload file to encrypt
Click Encrypt & Send
Share encrypted .enc file with receiver
🔹 Receiver Side
Open http://localhost:8502
Click Authenticate (Face + Fingerprint verification)
Upload encrypted .enc file
Click Decrypt File
Download original file
🔒 Security Features
1️⃣ BB84 Quantum Key Distribution
Simulated quantum key exchange protocol
Eavesdropping detection via basis mismatch (>15% error rate)
Session-based ephemeral keys (never reused)
Privacy amplification via SHA-256 hashing
2️⃣ Biometric Authentication
👤 Face Recognition
Model: ArcFace (Additive Angular Margin Loss)
Accuracy: 99.41% on LFW benchmark
Embedding: 512-dimensional vector
Similarity: Cosine similarity > 0.6 threshold
Detector: RetinaFace for face detection
🖐 Fingerprint Authentication
Hardware: Access FM220U L1 / ZFM-20 / R307 support
Template: Minutiae-based feature extraction
Matching: 1:1 verification against enrolled template
Fallback: Software simulation mode for development
3️⃣ Key Fusion Algorithm
Python
Copy
AES_Key = HKDF(
    algorithm=SHA256(),
    input_material=QKD_Key,  # 32 bytes
    salt=Random_Salt,         # 32 bytes (embedded in file)
    info="QKD-Biometric-Fusion-v1",
    output_length=32          # 256-bit AES key
)
Properties:
HKDF-SHA256 based derivation (RFC 5869)
256-bit AES key output
Biometrics as gates: Face/Fingerprint verify identity before key generation
Salt sharing: Embedded in encrypted file header (not secret)
4️⃣ Encryption
Algorithm: AES-256-GCM (Galois/Counter Mode)
Key Size: 256 bits (32 bytes)
Nonce: 96 bits (12 bytes), unique per encryption
Tag: 128 bits (16 bytes), authentication tag
Features:
Confidentiality (encryption)
Integrity (authentication tag)
Associated data support (metadata)
File Format:
plain
Copy
[salt_len: 2 bytes][salt: 32 bytes][nonce: 12 bytes][tag: 16 bytes][ciphertext]
📁 Project Structure
plain
Copy
QKD_Multimodal_Secure_Communication/
│
├── backend/
│   └── main.py              # FastAPI REST API server
│
├── frontend/
│   └── streamlit_app.py     # Streamlit web interface
│
├── scripts/
│   ├── enroll_face_sender.py       # Face enrollment (sender)
│   ├── enroll_face_receiver.py     # Face enrollment (receiver)
│   ├── enroll_fingerprint_sender.py    # Fingerprint enrollment (sender)
│   └── enroll_fingerprint_receiver.py  # Fingerprint enrollment (receiver)
│
├── data/
│   ├── faces/              # Face templates (hashed embeddings)
│   ├── fingerprints/       # Fingerprint templates
│   ├── keys/               # QKD keys (ephemeral)
│   └── temp/               # Temporary files
│
├── config.py               # System configuration
├── bb84.py                 # BB84 QKD implementation
├── face_auth.py            # Face recognition module
├── fingerprint_auth.py     # Fingerprint authentication
├── key_fusion.py           # HKDF key fusion
├── aes_crypto.py           # AES-256-GCM encryption
├── validators.py           # Input validation
├── ui_helpers.py           # UI utilities
├── requirements.txt        # Python dependencies
└── README.md               # This file
🧪 Testing
Run Unit Tests
bash
Copy
pytest tests/ -v
Test QKD Protocol
bash
Copy
curl -X POST "http://localhost:8000/qkd/generate?simulate_eavesdrop=false"
Test Biometric Enrollment
bash
Copy
python scripts/enroll_face_sender.py
python scripts/enroll_fingerprint_sender.py
Test API Authentication
bash
Copy
curl -X POST "http://localhost:8000/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"identity": "sender", "mode": "full"}'
🔧 Configuration
Edit config.py to customize:
Python
Copy
# Biometric thresholds
FACE_SIMILARITY_THRESHOLD = 0.6
FINGERPRINT_TIMEOUT = 30  # seconds

# QKD parameters
QKD_KEY_LENGTH = 256
BB84_ERROR_THRESHOLD = 0.15  # 15% eavesdropping threshold

# Encryption
AES_KEY_SIZE = 32  # 256 bits
AES_NONCE_SIZE = 12  # 96 bits for GCM
AES_TAG_SIZE = 16  # 128 bits

# Network
DEFAULT_BACKEND_PORT = 8000
DEFAULT_SENDER_PORT = 8501
DEFAULT_RECEIVER_PORT = 8502
📊 Performance
Table
Copy
Component	Time
Face Recognition	~1–2 sec
Fingerprint Auth	~0.5–1 sec
BB84 Key Generation	~0.1 sec
File Encryption (1MB)	~50 ms
Total Authentication	~3–5 sec
🛡️ Security Considerations
✅ Strengths
Multi-factor authentication: Biometric-based identity verification
Quantum-resistant key derivation: BB84 simulation with eavesdropping detection
No permanent key storage: Session-based ephemeral keys
Authenticated encryption: AES-256-GCM with integrity verification
Salt embedding: HKDF salt embedded in file (not secret, ensures key consistency)
⚠️ Limitations
BB84 is simulated: Not real quantum hardware (production: use ID Quantique/Toshiba)
Face embeddings stored locally: Templates are hashed, not raw images
Requires physical biometric presence: No remote authentication
Single-machine QKD: Seed sharing via API (production: use quantum channel)
🚀 Future Enhancements
[ ] Liveness detection for face authentication (anti-spoofing)
[ ] Hardware Security Module (HSM) integration
[ ] Real quantum key distribution hardware support
[ ] Multi-device secure sync
[ ] Blockchain-based audit logging
[ ] Post-quantum cryptography algorithms (CRYSTALS-Kyber)
[ ] Distributed QKD across multiple nodes
📚 References
Academic Papers
Bennett, C.H. & Brassard, G. (1984). "Quantum cryptography: Public key distribution and coin tossing." Proc. IEEE Int. Conf. Computers, Systems, and Signal Processing.
Deng, C., et al. (2019). "ArcFace: Additive Angular Margin Loss for Deep Face Recognition." CVPR 2019.
Krawczyk, H. (2010). "Cryptographic Extraction and Key Derivation: The HKDF Scheme." CRYPTO 2010.
Dworkin, M. (2007). "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)." NIST SP 800-38D.
Standards
BB84: Original quantum key distribution protocol
HKDF: RFC 5869 (HMAC-based Extract-and-Expand Key Derivation)
AES-GCM: NIST SP 800-38D
SHA-256: FIPS 180-4
👥 Contributors
Sandeep Rishi J B - @sandeeprishi
Rishikesh C - @rishikeshc
Rithish Anto A - @rithishanto
Shivam Kumar M - @shivamkumar
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🆘 Support
For issues, questions, or contributions:
🐛 GitHub Issues: Create an issue
📧 Email: jbsandeeprishi@gmail.com
💬 Discussions: GitHub Discussions
🙏 Acknowledgments
DeepFace - Face recognition library
FastAPI - Modern web framework
Streamlit - Data app framework
Qiskit - Quantum computing inspiration
Cryptography - Cryptographic primitives
<div align="center">
🔐 Secure Communication for the Quantum Age 🔐
Built with ❤️ using Python, FastAPI, Streamlit, and DeepFace
⭐ Star this repository if you find it useful! ⭐
</div>
