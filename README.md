# 🔐 QKD Multimodal Secure Communication System

A cutting-edge secure communication platform combining **Quantum Key Distribution (BB84)**, **multimodal biometric authentication** (Face + Fingerprint), and military-grade **AES-256 encryption**.

This system integrates quantum-resistant key exchange with real-time identity verification to provide next-generation secure communication over LAN networks.

---

## 🌟 Key Features

*   **🔑 BB84 Quantum Key Distribution** – Simulated quantum key exchange protocol
*   **👤 Multimodal Biometric Authentication**
    *   Face recognition (Deep Learning-based – ArcFace)
    *   Windows Hello fingerprint integration
*   **🔐 Key Fusion Technology** – Combines QKD + Face embeddings + Fingerprint token
*   **🛡️ End-to-End Encryption** – AES-256-GCM authenticated encryption
*   **⚡ Real-time Identity Verification** – Live continuous biometric validation during communication
*   **🌐 LAN Communication** – Secure file transfer over local networks

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    SENDER SIDE                              │
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
│                   RECEIVER SIDE                             │
├─────────────────────────────────────────────────────────────┤
│  1. Face Recognition (Live) ──────────┐                     │
│  2. Fingerprint Auth (Windows Hello) ─┼──→ Identity Verified│
│  3. BB84 QKD Key Reconstruction      ─┘                     │
│  4. Key Fusion → AES-256 Key                                │
│  5. Payload Decryption → Original File                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Prerequisites

*   **Python 3.9+**
*   **Windows 10/11** (for Windows Hello fingerprint support, fallback works on other OS)
*   **Webcam** (for live continuous face recognition)
*   **Fingerprint sensor** (FM220U or Windows Hello)

---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone <repository-url>
cd QKD_Multimodal_Secure_Communication
```

### 2️⃣ Create Virtual Environment
```bash
python -m venv venv
```

**Activate environment:**
*   Windows: `venv\Scripts\activate`
*   Mac/Linux: `source venv/bin/activate`

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🎯 Usage

To run the full multimodal secure communication suite, you need to spin up the backend component and two frontend instances for the sender and receiver.

### ▶ Start Backend Server
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### ▶ Launch Frontend UIs

**Terminal 1 – Login & Routing Panel**
```bash
streamlit run frontend/login_app.py --server.port 8501
```

**Terminal 2 – Main Operations Panel**
```bash
streamlit run frontend/streamlit_app.py --server.port 8502
```

---

## 🔄 Workflow Walkthrough

### 🔹 Sender Side
1. Open the Login App (Port 8501) and log in as the **Sender**.
2. Enroll biometrics in the **Enrollment Center** if not already completed.
3. Switch to the Main App (Port 8502) and execute **Live Authentication** (Face + Fingerprint).
4. Upload a file to encrypt.
5. Click **Encrypt & Download**. A continuous biometric security check will run in the background.
6. Share the downloaded `.enc` encrypted payload with the receiver.

### 🔹 Receiver Side
1. Log in as the **Receiver**.
2. Execute **Live Authentication**.
3. Upload the `.enc` encrypted payload received from the sender.
4. Click **Decrypt File**. A continuous background security check validates your identity.
5. Download the original restored file.

---

## 🔒 Security Features

### 1️⃣ BB84 Quantum Key Distribution
*   Simulated quantum key exchange.
*   Eavesdropping detection via basis mismatch.
*   Session-based keys (never reused).

### 2️⃣ Biometric Authentication
*   **👤 Face Recognition:** Powered by DeepFace (ArcFace model) with a Cosine similarity threshold of 0.6.
*   **🖐 Fingerprint Authentication:** Hardware integration with FM220U / Windows Hello.

### 3️⃣ Key Fusion Algorithm
A multi-factor entropy input combining keys utilizing HKDF-SHA256 based derivation into a 256-bit AES key.
```text
AES_Key = HKDF(
    input_material = QKD_Key || Face_Embedding || Fingerprint_Token,
    salt = random_salt,
    info = "QKD-Biometric-Fusion-v1",
    output_length = 32 bytes
)
```

### 4️⃣ Encryption
*   **AES-256-GCM** (Authenticated Encryption).
*   Unique nonce per encryption.
*   Authentication tag ensures total integrity verification.

---

## 📁 Project Structure
```text
QKD_Multimodal_Secure_Communication/
├── data/
│   ├── face_templates/      # Stored embedding representations
│   └── logs/
├── backend/
│   ├── main.py              # FastAPI endpoints
│   ├── qkd/                 # BB84 Quantum Protocol simulator
│   ├── crypto/              # AES-256 GCM engine
│   ├── biometrics/          # Face & Fingerprint verification 
│   └── security/            # Key Fusion logic
├── frontend/
│   ├── login_app.py         # Gatekeeper UI
│   ├── enrollment_app.py    # Biometric enrollment UI
│   └── streamlit_app.py     # Main operational dashboard
└── scripts/
```

---

## 📊 Performance Metrics

| Component | Estimated Time |
| :--- | :--- |
| Face Recognition | ~1–2 sec |
| Fingerprint Auth | ~0.5–1 sec |
| BB84 Key Generation | ~0.1 sec |
| File Encryption (1MB) | ~50 ms |
| **Total Authentication** | **~3–5 sec** |

---

## 🛡️ Security Considerations

### ✅ Strengths
*   Multi-factor authentication (Biometric-based) combined with continuous background security checking.
*   Quantum-resistant key derivation.
*   No permanent key storage (Session-based keys).
*   Authenticated encryption (AES-GCM).

### ⚠️ Limitations
*   BB84 is currently simulated via software rather than executing over real optic fiber hardware.
*   Face embeddings are stored locally (encrypted format).
*   Requires physical biometric presence for data operations.

---

## 👥 Contributors
*   **Sandeep Rishi J B**
*   **Rishikesh C**
*   **Rithishanto A**
*   **Shivam Kumar M**

## 🆘 Support
For issues and questions, please email: `jbsandeeprishi@gmail.com`

## 🙏 Acknowledgments
*   **DeepFace Library** (Face Recognition operations)
*   **Qiskit** (Quantum Computing inspiration)
*   **FastAPI & Streamlit** communities
