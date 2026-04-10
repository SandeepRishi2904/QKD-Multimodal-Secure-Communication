"""
QKD Multimodal Secure Communication System - FastAPI Backend
Provides REST API for encryption/decryption and biometric verification
"""
import os
import sys
import subprocess
import threading
import webbrowser
import time as _time
import json
import base64
import logging
import hashlib
import numpy as np
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
import tempfile

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

               
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

                                                         
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
sys.path.insert(0, str(parent_dir))

                    
from config import (
    TEMP_DIR, DEFAULT_HOST, DEFAULT_BACKEND_PORT, DEFAULT_SENDER_PORT,
    SENDER_FACE_TEMPLATE, RECEIVER_FACE_TEMPLATE,
    SENDER_FINGERPRINT_TEMPLATE, RECEIVER_FINGERPRINT_TEMPLATE,
    FINGERPRINT_SIMULATION
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

      
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

              
class AppState:
    def __init__(self):
        self.face_auth = FaceAuthenticator()
        self.fp_auth = FingerprintAuthenticator(use_simulation=FINGERPRINT_SIMULATION)
        self.key_fusion = KeyFusion()
        self.bb84 = BB84Protocol()
        self.active_sessions: Dict[str, Any] = {}
        self.shared_seed: Optional[bytes] = None
        self.shared_fusion_salt: Optional[bytes] = None
        self.sender_session_info: Optional[Dict] = None
                         
        self.shared_file_path: Optional[str] = None
        self.shared_file_name: Optional[str] = None
        self.shared_file_size: int = 0
        self.shared_file_ts:   Optional[str] = None
                                                                      
        self.shared_intended_receiver: Optional[str] = None

state = AppState()

                 
class AuthRequest(BaseModel):
    identity: str
    mode: str = 'full'
    simulate_eavesdrop: bool = False

class ContinuousAuthRequest(BaseModel):
    identity: str
    image: str                                 

class AuthResponse(BaseModel):
    success: bool
    face_verified: bool = False
    fingerprint_verified: bool = False
    face_confidence: float = 0.0
    fingerprint_confidence: float = 0.0
    message: str
    session_id: Optional[str] = None
    key_fingerprint: Optional[str] = None
    eavesdropping_detected: bool = False

class SwitchIdentityRequest(BaseModel):
    session_id: str
    new_identity: str
    current_identity: str

class FingerprintEnrollRequest(BaseModel):
    identity: str

              
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

                         
@app.get("/enrollment/{identity}")
async def check_enrollment(identity: str):
    """Check if identity is enrolled"""
    if identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")

    try:
        face_enrolled = state.face_auth.check_enrollment(identity)
        fp_enrolled = state.fp_auth.check_enrollment(identity)
        
        logger.info(f"Enrollment check for {identity}: face={face_enrolled}, fp={fp_enrolled}")

        return {
            "identity": identity,
            "face_enrolled": face_enrolled,
            "fingerprint_enrolled": fp_enrolled,
            "fully_enrolled": face_enrolled and fp_enrolled
        }
    except Exception as e:
        logger.error(f"Error checking enrollment: {e}")
                                                 
        return {
            "identity": identity,
            "face_enrolled": False,
            "fingerprint_enrolled": False,
            "fully_enrolled": False,
            "error": str(e)
        }

                                                                

@app.post("/enroll/face")
async def enroll_face(
    identity: str = Form(...),
    image: UploadFile = File(...)
):
    """
    Enroll face template from uploaded image or camera capture.
    """
    if identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")
    
    logger.info(f"Starting face enrollment for {identity}")
    
                              
    from config import FACE_DIR
    FACE_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    
                                     
    temp_path = TEMP_DIR / f"enroll_face_{identity}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
    
    try:
                            
        content = await image.read()
        with open(temp_path, 'wb') as f:
            f.write(content)
        
        logger.info(f"Saved temp image ({len(content)} bytes) to {temp_path}")
        
                                   
        import cv2
        img = cv2.imread(str(temp_path))
        
        if img is None:
            raise HTTPException(status_code=400, detail="Invalid image file - could not read with OpenCV")
        
        logger.info(f"Image loaded: {img.shape}")
        
                                                    
        success, message = state.face_auth.enroll_face(identity, image=img)
        
                            
        temp_path.unlink(missing_ok=True)
        
        if success:
            logger.info(f"✅ Face enrollment successful for {identity}")
            return {
                "success": True,
                "message": message,
                "identity": identity,
                "timestamp": datetime.now().isoformat()
            }
        else:
            logger.warning(f"❌ Face enrollment failed for {identity}: {message}")
            raise HTTPException(status_code=400, detail=message)
            
    except Exception as e:
                           
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        logger.error(f"Face enrollment error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Enrollment failed: {str(e)}")

@app.post("/enroll/fingerprint")
async def enroll_fingerprint(request: FingerprintEnrollRequest):
    """
    Enroll fingerprint template.
    Supports both hardware sensor and simulation mode.
    """
    identity = request.identity
    
    if identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")
    
    logger.info(f"Starting fingerprint enrollment for {identity}")
    
    try:
                                 
        from config import FINGERPRINT_DIR
        FINGERPRINT_DIR.mkdir(parents=True, exist_ok=True)
        
                                   
        if state.fp_auth.check_enrollment(identity):
            logger.info(f"Fingerprint already enrolled for {identity}, will overwrite...")
        
                            
        success, message = state.fp_auth.enroll_fingerprint(identity)
        
        if success:
            logger.info(f"✅ Fingerprint enrollment successful for {identity}")
            return {
                "success": True,
                "message": message,
                "identity": identity,
                "mode": "hardware" if state.fp_auth.is_hardware else "simulation",
                "timestamp": datetime.now().isoformat()
            }
        else:
            logger.warning(f"❌ Fingerprint enrollment failed for {identity}: {message}")
            raise HTTPException(status_code=400, detail=message)
            
    except Exception as e:
        logger.error(f"Fingerprint enrollment error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Enrollment failed: {str(e)}")

@app.get("/fingerprint/info")
async def get_fingerprint_info():
    """
    Get fingerprint sensor information.
    """
    try:
        info = state.fp_auth.get_sensor_info()
        return info
    except Exception as e:
        return {
            "mode": "unknown",
            "hardware": False,
            "status": "error",
            "error": str(e)
        }

                                                                    

                         
@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(request: AuthRequest):
    """
    Authenticate user with face and/or fingerprint.
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

                         
    if request.mode in ['face', 'full']:
        if not state.face_auth.check_enrollment(request.identity):
            return AuthResponse(
                success=False,
                message=f"Face not enrolled for {request.identity}. Please enroll first.",
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

                                
    if request.mode in ['fingerprint', 'full']:
        if not state.fp_auth.check_enrollment(request.identity):
            return AuthResponse(
                success=False,
                message=f"Fingerprint not enrolled for {request.identity}. Please enroll first.",
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

                                          
    if request.mode == 'full' and not (face_verified and fp_verified):
        failed = []
        if not face_verified:
            failed.append(f"Face (score: {face_confidence:.2f})")
        if not fp_verified:
            failed.append(f"Fingerprint (score: {fp_confidence:.2f})")
        return AuthResponse(
            success=False,
            message=f"Authentication failed — {' and '.join(failed)} did not verify. Try re-enrolling or use better lighting.",
            face_verified=face_verified,
            fingerprint_verified=fp_verified,
            face_confidence=face_confidence,
            fingerprint_confidence=fp_confidence
        )

                      
    if request.identity == "sender":
                                                                
        if state.shared_seed is None or request.simulate_eavesdrop:
            if request.simulate_eavesdrop:
                logger.warning("Simulating eavesdropping attack on QKD channel!")
                state.shared_seed = None                                          
            else:
                logger.info("Generating new QKD shared key...")
                
            bb84_result = state.bb84.generate_key(simulate_eavesdrop=request.simulate_eavesdrop)
            
            if bb84_result.eavesdropping_detected:
                logger.error("❌ Eavesdropping detected during key exchange! Aborting authentication.")
                return AuthResponse(
                    success=False,
                    message="SECURITY ALERT: Eavesdropping detected on quantum channel! Key exchange aborted.",
                    face_verified=face_verified,
                    fingerprint_verified=fp_verified,
                    eavesdropping_detected=True
                )
                
            state.shared_seed = bb84_result.key
        else:
            logger.info("Reusing existing QKD shared key...")
            class DummyResult:
                def __init__(self, key):
                    self.key = key
                    self.error_rate = 0.0
                    self.eavesdropping_detected = False
            bb84_result = DummyResult(state.shared_seed)

                                                     
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
                                                            
        if state.sender_session_info is None:
            return AuthResponse(
                success=False,
                message="Sender must authenticate first before receiver can authenticate",
                face_verified=face_verified,
                fingerprint_verified=fp_verified
            )

                                                            
        if not (face_verified and fp_verified):
            return AuthResponse(
                success=False,
                message="Receiver biometric authentication failed",
                face_verified=face_verified,
                fingerprint_verified=fp_verified
            )

        logger.info("✅ Receiver biometrics verified - using sender's key")
        
                                                               
        session_id = base64.urlsafe_b64encode(os.urandom(16)).decode()
        state.active_sessions[session_id] = {
            'identity': 'receiver',
            'aes_key': state.sender_session_info['aes_key'],
            'salt': state.sender_session_info['salt'],
            'qkd_key': state.sender_session_info['qkd_key'],
            'receiver_biometrics': {
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

@app.post("/authenticate/continuous")
async def authenticate_continuous(request: ContinuousAuthRequest):
    """
    Continuous background authentication for the sender
    Verifies base64 captured frame against enrolled template
    """
    if request.identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Invalid identity")
        
    try:
        if not state.face_auth.check_enrollment(request.identity):
            return {"success": False, "message": f"Face not enrolled for {request.identity}."}

                                
        img_data = request.image
        if "base64," in img_data:
            img_data = img_data.split("base64,")[1]
            
                                       
        img_bytes = base64.b64decode(img_data)
        np_arr = np.frombuffer(img_bytes, np.uint8)
        import cv2
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        
        if img is None:
            return {"success": False, "message": "Could not decode captured image"}
            
                     
        verified, confidence, msg = state.face_auth.verify_face(request.identity, image=img)
        
        return {
            "success": verified,
            "confidence": confidence,
            "message": msg
        }
    except Exception as e:
        logger.error(f"Continuous auth error: {e}")
        return {"success": False, "message": f"Error: {str(e)}"}

@app.post("/switch_identity")
async def switch_identity(request: SwitchIdentityRequest):
    """Check if identity switch is allowed."""
    if request.session_id not in state.active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if request.new_identity not in ['sender', 'receiver']:
        raise HTTPException(status_code=400, detail="Identity must be 'sender' or 'receiver'")
    
    session = state.active_sessions[request.session_id]
    
    if session['identity'] == request.new_identity:
        return {
            "success": True,
            "requires_authentication": False,
            "message": f"Already authenticated as {request.new_identity}",
            "session_id": request.session_id
        }
    
    if request.new_identity == "receiver" and state.sender_session_info is None:
        raise HTTPException(status_code=400, detail="Sender must authenticate first")
    
    if request.new_identity == "receiver":
        return {
            "success": True,
            "requires_authentication": True,
            "message": "Receiver authentication required",
            "session_id": request.session_id
        }
    
    return {
        "success": True,
        "requires_authentication": False,
        "message": f"Switched to {request.new_identity}",
        "session_id": request.session_id
    }

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

    if session['identity'] != 'sender':
        raise HTTPException(status_code=403, detail="Only sender can encrypt")

    is_valid, error_msg = SecurityValidator.validate_filename(file.filename)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    input_path = TEMP_DIR / file.filename
    with open(input_path, 'wb') as f:
        content = await file.read()
        f.write(content)

    is_valid, mime = SecurityValidator.validate_file_content(input_path)
    if not is_valid:
        input_path.unlink()
        raise HTTPException(status_code=400, detail=mime)

    try:
        crypto = AESCrypto(key=session['aes_key'])
        result = crypto.encrypt_file(input_path, compress=compress)

        output_path = Path(result['output_file'])
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

@app.post("/decrypt")
async def decrypt_file(
    session_id: str = Form(...),
    file: UploadFile = File(...)
):
    """Decrypt file using authenticated session"""
    if session_id not in state.active_sessions:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    session = state.active_sessions[session_id]

    if session['identity'] != 'receiver':
        raise HTTPException(status_code=403, detail="Only receiver can decrypt")

    input_path = TEMP_DIR / file.filename
    with open(input_path, 'wb') as f:
        content = await file.read()
        f.write(content)

    try:
        crypto = AESCrypto(key=session['aes_key'])
        result = crypto.decrypt_file(input_path)

        output_path = Path(result['output_file'])
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
        import traceback
        tb = traceback.format_exc()
        logger.error(f"Decryption failed: {e}\n{tb}")
        
        error_msg = str(e) if str(e) else e.__class__.__name__
        raise HTTPException(status_code=400, detail=f"Decryption failed: {error_msg}")

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

                                                                
                                                            
                                                                 

@app.post("/share/upload")
async def share_upload(
    file: UploadFile = File(...),
    sender_username: str = Form(...),
    intended_receiver: str = Form(...),
):
    """Sender uploads .enc file to relay it to a specific receiver.
    
    Requires sender_username (must be a registered sender/both role) and
    intended_receiver username (must be a registered receiver/both role).
    Only the designated receiver will be allowed to fetch this file.
    """
                                     
    import json as _json_users
    users_path = Path(__file__).parent.parent / "data" / "users.json"
    try:
        with open(users_path) as _uf:
            _all_users = _json_users.load(_uf)
    except Exception:
        _all_users = {}

                     
    if sender_username not in _all_users:
        raise HTTPException(status_code=401, detail=f"Sender '{sender_username}' not found in user database")
    if _all_users[sender_username].get("role") not in ("sender", "both"):
        raise HTTPException(status_code=403, detail=f"'{sender_username}' does not have sender privileges")

                                
    if intended_receiver not in _all_users:
        raise HTTPException(status_code=400, detail=f"Receiver '{intended_receiver}' not found in user database")
    if _all_users[intended_receiver].get("role") not in ("receiver", "both"):
        raise HTTPException(status_code=400, detail=f"'{intended_receiver}' is not a receiver account")

    TEMP_DIR.mkdir(parents=True, exist_ok=True)

                                        
    if state.shared_file_path and Path(state.shared_file_path).exists():
        try:
            Path(state.shared_file_path).unlink()
        except Exception:
            pass

    safe_name = Path(file.filename).name or "shared_payload.enc"
    dest = TEMP_DIR / f"shared__{safe_name}"
    content = await file.read()
    with open(dest, "wb") as f:
        f.write(content)

    state.shared_file_path = str(dest)
    state.shared_file_name = safe_name
    state.shared_file_size = len(content)
    state.shared_file_ts   = datetime.now().isoformat()
    state.shared_intended_receiver = intended_receiver

    logger.info(f"📤 '{sender_username}' uploaded: {safe_name} ({len(content):,} bytes) → intended for '{intended_receiver}'")
    return {
        "success": True,
        "filename": safe_name,
        "size": len(content),
        "timestamp": state.shared_file_ts,
        "intended_receiver": intended_receiver,
    }


@app.get("/share/status")
async def share_status(requester_username: Optional[str] = None):
    """Receiver checks whether a shared file is waiting for them.
    
    requester_username must match the intended_receiver set by the sender.
    Without a valid requester, the file is not revealed.
    """
    if not state.shared_file_path or not Path(state.shared_file_path).exists():
        return {"available": False}

                                                                                                    
    if state.shared_intended_receiver is None:
        return {"available": False, "error": "File has no designated receiver — contact sender"}

                                                          
    if not requester_username or requester_username.strip() != state.shared_intended_receiver:
        logger.warning(f"🚫 Unauthorised status check by '{requester_username}' (intended: '{state.shared_intended_receiver}')")
        return {"available": False}                                              

    return {
        "available": True,
        "filename": state.shared_file_name,
        "size": state.shared_file_size,
        "timestamp": state.shared_file_ts,
    }


@app.get("/share/download")
async def share_download(requester_username: Optional[str] = None):
    """Receiver downloads the shared .enc file.
    
    requester_username must match the intended_receiver chosen by the sender.
    Any other user gets a 403 Forbidden.
    """
    if not state.shared_file_path or not Path(state.shared_file_path).exists():
        raise HTTPException(status_code=404, detail="No shared file available")

                                  
    if state.shared_intended_receiver is not None:
        if not requester_username or requester_username.strip() != state.shared_intended_receiver:
            logger.warning(f"🚫 Unauthorised download attempt by '{requester_username}' (intended: '{state.shared_intended_receiver}')")
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. This file was not shared with you."
            )
    else:
                                                                                    
        raise HTTPException(status_code=403, detail="File has no designated receiver — sender must re-upload")

    path = Path(state.shared_file_path)
    name = state.shared_file_name or path.name

    logger.info(f"📥 Shared file downloaded by '{requester_username}': {name}")
    return FileResponse(
        path,
        filename=name,
        media_type="application/octet-stream",
    )

                                                                    

@app.on_event("startup")

async def startup_event():
    logger.info("🚀 QKD Multimodal API starting up...")

    try:
        sender_face = state.face_auth.check_enrollment('sender')
        sender_fp = state.fp_auth.check_enrollment('sender')
        receiver_face = state.face_auth.check_enrollment('receiver')
        receiver_fp = state.fp_auth.check_enrollment('receiver')
        
        sender_ready = sender_face and sender_fp
        receiver_ready = receiver_face and receiver_fp

        logger.info(f"Sender enrollment: {'✅' if sender_ready else '❌'} (face: {sender_face}, fp: {sender_fp})")
        logger.info(f"Receiver enrollment: {'✅' if receiver_ready else '❌'} (face: {receiver_face}, fp: {receiver_fp})")

        if not (sender_ready and receiver_ready):
            logger.warning("⚠️  Not all identities enrolled. UI enrollment available at /enrollment endpoints.")
    except Exception as e:
        logger.error(f"Error checking enrollment on startup: {e}")

def _launch_frontend():
    """Launch Streamlit frontend in a background subprocess (Windows-safe)."""
    import shutil, traceback, platform

    project_root = Path(__file__).parent.parent
    frontend_script = project_root / "frontend" / "app.py"
    frontend_port = DEFAULT_SENDER_PORT        

    logger.info(f"🖥  Launching Streamlit frontend → http://localhost:{frontend_port}")
    try:
        if platform.system() == "Windows":
                                                                                   
            cmd = (
                f'streamlit run "{frontend_script}" '
                f'--server.port {frontend_port} '
                f'--server.headless true '
                f'--browser.gatherUsageStats false'
            )
            subprocess.Popen(cmd, cwd=str(project_root), shell=True)
        else:
            streamlit_exe = shutil.which("streamlit") or sys.executable
            cmd = ([streamlit_exe, "run", str(frontend_script)] if shutil.which("streamlit")
                   else [sys.executable, "-m", "streamlit", "run", str(frontend_script)])
            cmd += ["--server.port", str(frontend_port),
                    "--server.headless", "true",
                    "--browser.gatherUsageStats", "false"]
            subprocess.Popen(cmd, cwd=str(project_root))

                                                                
        _time.sleep(4)
        webbrowser.open(f"http://localhost:{frontend_port}")
        logger.info(f"✅ Browser opened at http://localhost:{frontend_port}")
    except Exception as exc:
        logger.error(f"❌ Could not launch frontend: {exc}")
        logger.error(traceback.format_exc())


if __name__ == "__main__":
                                                                       
    frontend_thread = threading.Thread(target=_launch_frontend, daemon=True)
    frontend_thread.start()

    uvicorn.run(
        "main:app",
        host=DEFAULT_HOST,
        port=DEFAULT_BACKEND_PORT,
        reload=False,                                                                
        log_level="info"
    )