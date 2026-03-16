"""
Key Fusion Module
Combines QKD key with biometric data (face + fingerprint) using HKDF
"""
import os
import hashlib
import logging
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from config import HKDF_INFO, SALT_SIZE, AES_KEY_SIZE

logger = logging.getLogger(__name__)

class KeyFusion:
    """
    Fuses QKD key with biometric data using HKDF (HMAC-based Extract-and-Expand Key Derivation Function)

    Formula: AES_Key = HKDF(input_material=QKD_Key || Face_Hash || Fingerprint_Hash, salt, info)
    """

    def __init__(self):
        self.salt_size = SALT_SIZE
        self.info = HKDF_INFO

    def fuse_keys(self, qkd_key: bytes, face_hash: Optional[bytes] = None, 
                  fingerprint_hash: Optional[bytes] = None, 
                  salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Fuse multiple key materials into single AES-256 key

        Args:
            qkd_key: QKD generated key (32 bytes)
            face_hash: Face embedding hash (32 bytes)
            fingerprint_hash: Fingerprint template hash (32 bytes)
            salt: Optional salt (generates random if None)

        Returns:
            (fused_key, salt)
        """
        if salt is None:
            salt = os.urandom(self.salt_size)

        # Combine input materials
        input_material = qkd_key

        if face_hash:
            input_material += face_hash
            logger.debug("Added face hash to key fusion")

        if fingerprint_hash:
            input_material += fingerprint_hash
            logger.debug("Added fingerprint hash to key fusion")

        # Use HKDF for key derivation
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            info=self.info,
            backend=default_backend()
        )

        fused_key = hkdf.derive(input_material)

        logger.info(f"✅ Key fusion complete: {len(fused_key)} bytes")
        logger.debug(f"Input material: {len(input_material)} bytes")

        return fused_key, salt

    def fuse_with_verification(self, qkd_key: bytes, 
                              face_auth_result: Tuple[bool, float, bytes],
                              fingerprint_auth_result: Tuple[bool, float, bytes],
                              require_both: bool = True) -> Dict[str, Any]:
        """
        Fuse keys with authentication verification

        Args:
            qkd_key: QKD key
            face_auth_result: (verified, confidence, face_hash)
            fingerprint_auth_result: (verified, confidence, fingerprint_hash)
            require_both: If True, both biometrics must pass

        Returns:
            Dict with 'success', 'key', 'salt', 'face_verified', 'fingerprint_verified'
        """
        face_verified, face_confidence, face_hash = face_auth_result
        fp_verified, fp_confidence, fp_hash = fingerprint_auth_result

        # Check verification status
        if require_both:
            if not (face_verified and fp_verified):
                logger.error("❌ Both biometrics required but not verified")
                return {
                    'success': False,
                    'error': 'Both face and fingerprint verification required',
                    'face_verified': face_verified,
                    'fingerprint_verified': fp_verified,
                    'face_confidence': face_confidence,
                    'fingerprint_confidence': fp_confidence
                }
        else:
            if not (face_verified or fp_verified):
                logger.error("❌ At least one biometric required but none verified")
                return {
                    'success': False,
                    'error': 'At least one biometric verification required',
                    'face_verified': face_verified,
                    'fingerprint_verified': fp_verified
                }

        # Perform key fusion
        fused_key, salt = self.fuse_keys(
            qkd_key=qkd_key,
            face_hash=face_hash if face_verified else None,
            fingerprint_hash=fp_hash if fp_verified else None
        )

        return {
            'success': True,
            'key': fused_key,
            'salt': salt,
            'face_verified': face_verified,
            'fingerprint_verified': fp_verified,
            'face_confidence': face_confidence,
            'fingerprint_confidence': fp_confidence,
            'key_fingerprint': hashlib.sha256(fused_key).hexdigest()[:16]
        }

    def regenerate_key(self, qkd_key: bytes, salt: bytes, 
                       face_hash: Optional[bytes] = None,
                       fingerprint_hash: Optional[bytes] = None) -> bytes:
        """
        Regenerate same key with known salt (for receiver side)
        """
        return self.fuse_keys(qkd_key, face_hash, fingerprint_hash, salt)[0]

    @staticmethod
    def generate_shared_seed() -> bytes:
        """Generate shared seed for deterministic QKD (must be shared via secure channel)"""
        return os.urandom(32)

    def verify_key_integrity(self, key1: bytes, key2: bytes) -> bool:
        """Verify two keys match"""
        return key1 == key2

class DeterministicKeyFusion(KeyFusion):
    """
    Deterministic key fusion for synchronized sender/receiver
    Uses shared seed for reproducible key generation
    """

    def __init__(self, shared_seed: bytes):
        super().__init__()
        self.shared_seed = shared_seed

    def generate_deterministic_fusion(self, qkd_key: bytes,
                                       face_hash: Optional[bytes] = None,
                                       fingerprint_hash: Optional[bytes] = None) -> bytes:
        """
        Generate deterministic fused key using shared seed as salt
        Both sender and receiver will generate identical keys
        """
        # Use shared seed as salt (must be pre-shared via secure channel)
        return self.fuse_keys(qkd_key, face_hash, fingerprint_hash, self.shared_seed)[0]
