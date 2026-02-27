"""
QKD Multimodal Secure Communication System - FastAPI Backend
Provides REST API for encryption/decryption and biometric verification
"""
import os
import sys
import json
import base64
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import tempfile

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our modules
from config import (
    TEMP_DIR, DEFAULT_HOST, DEFAULT_BACKEND_PORT,
    SENDER_FACE_TEMPLATE, RECEIVER_FACE_TEMPLATE,
    SENDER_FINGERPRINT_TEMPLATE, RECEIVER_FINGERPRINT_TEMPLATE
)
from bb84 import BB84Protocol
from face_auth import FaceAuthenticator
from fingerprint_auth import FingerprintAuthenticator
from key_fusion import KeyFusion
from aes_crypto import AESCrypto
from security_validators import SecurityValidator

app = FastAPI(
    title="QKD Multimodal Secure Communication API",
    description="Quantum Key Distribution with Multimodal Biometric Authentication",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
class AppState:
    def __init__(self):
        self.face_auth = FaceAuthenticator()
        self.fp_auth = FingerprintAuthenticator(use_simulation=False)
        self.key_fusion = KeyFusion()
        self.bb84 = BB84Protocol()
        self.active_sessions: Dict[str, Any] = {}
        self.shared_seed: Optional[bytes] = None
        self.shared_fusion_salt: Optional[bytes] = None
        self.sender_session_info: Optional[Dict] = None  # ← ADDED: Store sender's key for receiver

state = AppState()

# Pydantic models
class AuthRequest(BaseModel):
    identity: str  # 'sender' or 'receiver'
    mode: str = 'full'  # 'face', 'fingerprint', or 'full'

class AuthResponse(BaseModel):
    success: bool
    face_verified: bool = False
    fingerprint_verified: bool = False
    face_confidence: float = 0.0
    fingerprint_confidence: float = 0.0
    message: str
    session_id: Optional[str] = None
    key_fingerprint: Optional[str] = None

class SwitchIdentityRequest(BaseModel):
    session_id: str
    new_identity: str
    current_identity: str

# Health check
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "QKD Multimodal Secure Communication API",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "face_auth": state.face_auth.model is not None,
        "fp_auth": True,
        "timestamp": datetime.now().isoformat()
    }

# Enrollment status check
@app.get("/enrollment/{identity}")
async def check_enrollment(identity: str):
    """Check if identity is enrolled"""
    if identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")

    face_enrolled = state.face_auth.check_enrollment(identity)
    fp_enrolled = state.fp_auth.check_enrollment(identity)

    return {
        "identity": identity,
        "face_enrolled": face_enrolled,
        "fingerprint_enrolled": fp_enrolled,
        "fully_enrolled": face_enrolled and fp_enrolled
    }

# Authentication endpoint
@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(request: AuthRequest):
    """
    Authenticate user with face and/or fingerprint.
    Sender generates the key, receiver verifies biometrics and uses sender's key.
    """
    if request.identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")

    logger.info(f"Starting authentication for {request.identity} (mode: {request.mode})")

    face_verified = False
    fp_verified = False
    face_confidence = 0.0
    fp_confidence = 0.0
    face_hash = None
    fp_hash = None

    # Face authentication
    if request.mode in ['face', 'full']:
        if not state.face_auth.check_enrollment(request.identity):
            return AuthResponse(
                success=False,
                message=f"Face not enrolled for {request.identity}",
                face_verified=False,
                fingerprint_verified=False
            )

        logger.info(f"Capturing face for {request.identity} verification...")
        face_verified, face_confidence, msg = state.face_auth.verify_face(request.identity)

        if face_verified:
            face_hash = state.face_auth.get_embedding_for_fusion(request.identity)
            logger.info(f"✅ Face verified: {face_confidence:.3f}")
        else:
            logger.warning(f"❌ Face verification failed: {msg}")
            if request.mode == 'face':
                return AuthResponse(
                    success=False,
                    message=msg,
                    face_verified=False,
                    fingerprint_verified=False
                )

    # Fingerprint authentication
    if request.mode in ['fingerprint', 'full']:
        if not state.fp_auth.check_enrollment(request.identity):
            return AuthResponse(
                success=False,
                message=f"Fingerprint not enrolled for {request.identity}",
                face_verified=face_verified,
                fingerprint_verified=False
            )

        logger.info(f"Capturing fingerprint for {request.identity} verification...")
        fp_verified, fp_confidence, msg = state.fp_auth.verify_fingerprint(request.identity)

        if fp_verified:
            fp_hash = state.fp_auth.get_template_for_fusion(request.identity)
            logger.info(f"✅ Fingerprint verified: {fp_confidence:.3f}")
        else:
            logger.warning(f"❌ Fingerprint verification failed: {msg}")
            if request.mode == 'fingerprint':
                return AuthResponse(
                    success=False,
                    message=msg,
                    face_verified=face_verified,
                    fingerprint_verified=False
                )

    # Check if both required for full mode
    if request.mode == 'full' and not (face_verified and fp_verified):
        return AuthResponse(
            success=False,
            message="Both face and fingerprint verification required",
            face_verified=face_verified,
            fingerprint_verified=fp_verified,
            face_confidence=face_confidence,
            fingerprint_confidence=fp_confidence
        )

    # ─────────────────────────────────────────────────────────────
    # KEY FUSION LOGIC (FIXED - Sender generates key, Receiver uses it)
    # ─────────────────────────────────────────────────────────────
    
    if request.identity == "sender":
        # SENDER: Generate QKD key and create the encryption key
        if state.shared_seed is None:
            logger.info("Generating new QKD shared key...")
            bb84_result = state.bb84.generate_key()
            state.shared_seed = bb84_result.key
        else:
            logger.info("Reusing existing QKD shared key...")
            class DummyResult:
                def __init__(self, key):
                    self.key = key
                    self.error_rate = 0.0
                    self.eavesdropping_detected = False
            bb84_result = DummyResult(state.shared_seed)

        # Generate fused key with sender's biometrics
        fusion_result = state.key_fusion.fuse_with_verification(
            qkd_key=bb84_result.key,
            face_auth_result=(face_verified, face_confidence, face_hash),
            fingerprint_auth_result=(fp_verified, fp_confidence, fp_hash),
            require_both=(request.mode == 'full')
        )

        if not fusion_result['success']:
            return AuthResponse(
                success=False,
                message=fusion_result.get('error', 'Key fusion failed'),
                face_verified=face_verified,
                fingerprint_verified=fp_verified
            )

        # Store sender's session info globally for receiver to use
        state.shared_fusion_salt = fusion_result['salt']
        state.sender_session_info = {
            'qkd_key': bb84_result.key,
            'salt': fusion_result['salt'],
            'aes_key': fusion_result['key'],
            'sender_biometrics': {
                'face_confidence': face_confidence,
                'fingerprint_confidence': fp_confidence
            }
        }

        # Create sender session
        session_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
        state.active_sessions[session_id] = {
            'identity': 'sender',
            'aes_key': fusion_result['key'],
            'salt': fusion_result['salt'],
            'qkd_key': bb84_result.key,
            'created_at': datetime.now().isoformat(),
            'qkd_stats': {
                'error_rate': bb84_result.error_rate,
                'eavesdropping_detected': bb84_result.eavesdropping_detected
            }
        }

        logger.info(f"✅ Sender authentication successful, session: {session_id[:8]}...")

        return AuthResponse(
            success=True,
            face_verified=face_verified,
            fingerprint_verified=fp_verified,
            face_confidence=face_confidence,
            fingerprint_confidence=fp_confidence,
            message="Sender authentication successful",
            session_id=session_id,
            key_fingerprint=fusion_result['key_fingerprint']
        )

    else:
        # RECEIVER: Verify biometrics, then use sender's key (don't regenerate)
        if state.sender_session_info is None:
            return AuthResponse(
                success=False,
                message="Sender must authenticate first before receiver can authenticate",
                face_verified=face_verified,
                fingerprint_verified=fp_verified
            )

        # Verify receiver's biometrics passed authentication
        if not (face_verified and fp_verified):
            return AuthResponse(
                success=False,
                message="Receiver biometric authentication failed",
                face_verified=face_verified,
                fingerprint_verified=fp_verified
            )

        logger.info("✅ Receiver biometrics verified - using sender's key")
        
        # Create receiver session with SENDER's key (same key!)
        session_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
        state.active_sessions[session_id] = {
            'identity': 'receiver',
            'aes_key': state.sender_session_info['aes_key'],  # ← Same key as sender!
            'salt': state.sender_session_info['salt'],
            'qkd_key': state.sender_session_info['qkd_key'],
            'receiver_biometrics': {  # Store for audit trail
                'face_confidence': face_confidence,
                'fingerprint_confidence': fp_confidence
            },
            'created_at': datetime.now().isoformat(),
            'qkd_stats': {
                'error_rate': 0.0,
                'eavesdropping_detected': False
            }
        }

        logger.info(f"✅ Receiver authentication successful, session: {session_id[:8]}...")

        return AuthResponse(
            success=True,
            face_verified=face_verified,
            fingerprint_verified=fp_verified,
            face_confidence=face_confidence,
            fingerprint_confidence=fp_confidence,
            message="Receiver authentication successful",
            session_id=session_id,
            key_fingerprint=hashlib.sha256(state.sender_session_info['aes_key']).hexdigest()[:16]
        )

@app.post("/switch_identity")
async def switch_identity(request: SwitchIdentityRequest):
    """
    Check if identity switch is allowed.
    """
    if request.session_id not in state.active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if request.new_identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")
    
    session = state.active_sessions[request.session_id]
    
    # Check if trying to switch to same identity
    if session['identity'] == request.new_identity:
        return {
            "success": True,
            "requires_authentication": False,
            "message": f"Already authenticated as {request.new_identity}",
            "session_id": request.session_id
        }
    
    # Check if sender info exists for receiver to use
    if request.new_identity == "receiver" and state.sender_session_info is None:
        raise HTTPException(status_code=400, detail="Sender must authenticate first")
    
    # Receiver needs separate authentication
    if request.new_identity == "receiver":
        return {
            "success": True,
            "requires_authentication": True,
            "message": "Receiver authentication required",
            "session_id": request.session_id
        }
    
    # Switching back to sender (if already authenticated)
    return {
        "success": True,
        "requires_authentication": False,
        "message": f"Switched to {request.new_identity}",
        "session_id": request.session_id
    }

# File encryption endpoint
@app.post("/encrypt")
async def encrypt_file(
    session_id: str = Form(...),
    file: UploadFile = File(...),
    compress: bool = Form(True)
):
    """Encrypt file using authenticated session"""

    if session_id not in state.active_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    session = state.active_sessions[session_id]

    # Only sender can encrypt
    if session['identity'] != 'sender':
        raise HTTPException(status_code=403, detail="Only sender can encrypt")

    # Validate filename
    is_valid, error_msg = SecurityValidator.validate_filename(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Save uploaded file
    input_path = TEMP_DIR / file.filename
    with open(input_path, 'wb') as f:
        content = await file.read()
        f.write(content)

    # Validate file content
    is_valid, mime = SecurityValidator.validate_file_content(input_path)
    if not is_valid:
        input_path.unlink()
        raise HTTPException(status_code=400, detail=mime)

    try:
        # Encrypt
        crypto = AESCrypto(key=session['aes_key'])
        result = crypto.encrypt_file(input_path, compress=compress)

        output_path = Path(result['output_file'])

        # Clean up input
        input_path.unlink()

        logger.info(f"✅ Encrypted: {file.filename} -> {output_path.name}")

        return FileResponse(
            output_path,
            filename=output_path.name,
            media_type='application/octet-stream',
            headers={
                'X-Encryption-Metadata': json.dumps(result['metadata'])
            }
        )

    except Exception as e:
        if input_path.exists():
            input_path.unlink()
        logger.error(f"Encryption failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# File decryption endpoint
@app.post("/decrypt")
async def decrypt_file(
    session_id: str = Form(...),
    file: UploadFile = File(...)
):
    """Decrypt file using authenticated session"""

    if session_id not in state.active_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    session = state.active_sessions[session_id]

    # Only receiver can decrypt
    if session['identity'] != 'receiver':
        raise HTTPException(status_code=403, detail="Only receiver can decrypt")

    # Save uploaded file
    input_path = TEMP_DIR / file.filename
    with open(input_path, 'wb') as f:
        content = await file.read()
        f.write(content)

    try:
        # Decrypt
        crypto = AESCrypto(key=session['aes_key'])
        result = crypto.decrypt_file(input_path)

        output_path = Path(result['output_file'])

        # Clean up encrypted file
        input_path.unlink()

        logger.info(f"✅ Decrypted: {file.filename} -> {output_path.name}")

        return FileResponse(
            output_path,
            filename=result['original_name'] or output_path.name,
            media_type='application/octet-stream',
            headers={
                'X-Decryption-Metadata': json.dumps(result['metadata'])
            }
        )

    except Exception as e:
        if input_path.exists():
            input_path.unlink()
        logger.error(f"Decryption failed: {e}")
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

# QKD key generation (for advanced use)
@app.post("/qkd/generate")
async def generate_qkd_key(simulate_eavesdrop: bool = False):
    """Generate BB84 QKD key"""
    try:
        result = state.bb84.generate_key(simulate_eavesdrop=simulate_eavesdrop)

        return {
            "success": True,
            "key_length": result.final_key_length,
            "error_rate": result.error_rate,
            "eavesdropping_detected": result.eavesdropping_detected,
            "raw_key_length": result.raw_key_length,
            "key_preview": base64.b64encode(result.key[:8]).decode() + "..."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Session management
@app.get("/session/{session_id}")
async def get_session(session_id: str):
    """Get session info (without sensitive data)"""
    if session_id not in state.active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    session = state.active_sessions[session_id]
    return {
        "identity": session['identity'],
        "created_at": session['created_at'],
        "qkd_stats": session.get('qkd_stats', {}),
        "active": True
    }

@app.delete("/session/{session_id}")
async def close_session(session_id: str):
    """Close and invalidate session"""
    if session_id in state.active_sessions:
        del state.active_sessions[session_id]
        return {"success": True, "message": "Session closed"}
    raise HTTPException(status_code=404, detail="Session not found")

# Cleanup old sessions periodically
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 QKD Multimodal API starting up...")

    # Check enrollments
    sender_ready = state.face_auth.check_enrollment('sender') and state.fp_auth.check_enrollment('sender')
    receiver_ready = state.face_auth.check_enrollment('receiver') and state.fp_auth.check_enrollment('receiver')

    logger.info(f"Sender enrollment: {'✅' if sender_ready else '❌'}")
    logger.info(f"Receiver enrollment: {'✅' if receiver_ready else '❌'}")

    if not (sender_ready and receiver_ready):
        logger.warning("⚠️  Not all identities enrolled. Run enrollment scripts first.")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=DEFAULT_HOST,
        port=DEFAULT_BACKEND_PORT,
        reload=True,
        log_level="info"
    )