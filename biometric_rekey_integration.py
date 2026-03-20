"""
Biometric Re-key Integration — All Three Innovations Wired Together

This module is the single entry point that combines:

    INNOVATION 1 — Biometric Quantum Entropy Seeding (BQES)
        bb84.BB84Protocol.generate_key(face_embedding=..., fingerprint_token=...)

    INNOVATION 2 — Quantum Noise Liveness Detection (QNLD)
        bb84.BB84Protocol.check_liveness(user_id, error_rate)

    INNOVATION 3 — Biometric-Confidence-Driven Adaptive Re-keying
        key_fusion.AdaptiveRekeyMonitor + aes_crypto.AESCrypto.update_key()

Usage (Sender side):
    session = SecureSessionManager(
        user_id="alice",
        face_embedding=deepface_result["embedding"],
        fingerprint_token=windows_hello_token,
        enrolled_face_embedding=stored_embedding,
        get_live_embedding=lambda: camera.get_embedding(),
    )
    session.start()

    # Encrypt a file
    result = session.encrypt_file("secret.pdf")

    # At any point, the key may have been rotated by Innovation 3.
    # session.aes.rekey_log shows the full history.

    session.stop()

Usage (Receiver side):
    session = SecureSessionManager(
        user_id="bob",
        face_embedding=deepface_result["embedding"],
        fingerprint_token=windows_hello_token,
        enrolled_face_embedding=stored_embedding,
        get_live_embedding=lambda: camera.get_embedding(),
        qkd_shared_seed=received_seed,     # pre-shared via secure channel
        fusion_salt=received_salt,          # transmitted with the encrypted file
    )
    session.start()
    result = session.decrypt_file("secret.pdf.enc")
    session.stop()
"""

import logging
import time
from typing import Optional, List, Callable, Dict, Any

from bb84 import BB84Protocol, DeterministicBB84, BB84Result
from key_fusion import KeyFusion, BiometricEntropyExtractor, AdaptiveRekeyMonitor
from aes_crypto import AESCrypto

logger = logging.getLogger(__name__)


class SecureSessionManager:
    """
    Unified session manager integrating all three innovations.

    Lifecycle:
        1. __init__  — prepare biometric seeds (BQES)
        2. start()   — run BB84 + liveness check + fuse key + start monitor
        3. encrypt/decrypt calls — use active AES key (may rotate mid-session)
        4. stop()    — tear down monitor, log stats
    """

    def __init__(
        self,
        user_id: str,
        face_embedding: List[float],
        fingerprint_token: Any,
        enrolled_face_embedding: List[float],
        get_live_embedding: Callable[[], Optional[List[float]]],
        qkd_shared_seed: Optional[bytes] = None,
        fusion_salt: Optional[bytes] = None,
        enable_liveness: bool = True,
        enable_adaptive_rekey: bool = True,
    ):
        self.user_id = user_id
        self.face_embedding = face_embedding
        self.fingerprint_token = fingerprint_token
        self.enrolled_face_embedding = enrolled_face_embedding
        self.get_live_embedding = get_live_embedding
        self.qkd_shared_seed = qkd_shared_seed
        self.fusion_salt = fusion_salt
        self.enable_liveness = enable_liveness
        self.enable_adaptive_rekey = enable_adaptive_rekey

        self.extractor = BiometricEntropyExtractor()
        self.fusion = KeyFusion()
        self.bb84 = BB84Protocol(key_length=256)

        self.aes: Optional[AESCrypto] = None
        self.monitor: Optional[AdaptiveRekeyMonitor] = None
        self.session_bb84_result: Optional[BB84Result] = None
        self._started = False

    # ── INNOVATION 1 + 2: Session startup ─────────────────────────────────────

    def start(self) -> Dict[str, Any]:
        """
        Start the secure session.

        Steps:
            1. Convert biometrics to BQES seeds (Innovation 1).
            2. Run BB84 with biometric-seeded bases (Innovation 1).
            3. Run quantum noise liveness check (Innovation 2).
            4. Fuse QKD key + biometric seeds → AES-256 key.
            5. Start adaptive re-key monitor (Innovation 3).

        Returns:
            Dict with session start metadata.
        """
        logger.info(f"[Session] Starting secure session for '{self.user_id}'")

        # ── Step 1: BQES — convert embeddings to seed bytes ──────────────────
        face_seed = self.extractor.face_embedding_to_bytes(self.face_embedding)
        fp_seed = self.extractor.fingerprint_token_to_bytes(self.fingerprint_token)

        # ── Step 2: BB84 with biometric-seeded bases ──────────────────────────
        if self.qkd_shared_seed:
            det_bb84 = DeterministicBB84(seed=self.qkd_shared_seed)
            bb84_result = det_bb84.generate_deterministic_key(
                face_embedding=face_seed,
                fingerprint_token=fp_seed,
                user_id=self.user_id if self.enable_liveness else None,
            )
        else:
            bb84_result = self.bb84.generate_key(
                face_embedding=face_seed,
                fingerprint_token=fp_seed,
                user_id=self.user_id if self.enable_liveness else None,
                enable_liveness_check=self.enable_liveness,
            )

        self.session_bb84_result = bb84_result

        # ── Step 3: Liveness gate ─────────────────────────────────────────────
        if self.enable_liveness and bb84_result.liveness_passed is False:
            logger.error(f"[Session] BLOCKED — liveness check failed for '{self.user_id}'")
            raise PermissionError(
                f"Quantum noise liveness check failed for user '{self.user_id}'. "
                f"Deviation={bb84_result.liveness_deviation:.4f}. "
                "Possible replay/spoofing attack detected."
            )

        # ── Step 4: Key fusion → AES-256 ─────────────────────────────────────
        fused_key, salt = self.fusion.fuse_keys(
            qkd_key=bb84_result.key,
            face_hash=face_seed,
            fingerprint_hash=fp_seed,
            salt=self.fusion_salt,
        )
        self.fusion_salt = salt
        self.aes = AESCrypto(key=fused_key)

        logger.info(
            f"[Session] AES key ready — fingerprint={self.aes.get_key_fingerprint()}, "
            f"BQES={'yes' if bb84_result.biometric_seeded else 'no'}, "
            f"liveness={'passed' if bb84_result.liveness_passed is not False else 'skipped'}"
        )

        # ── Step 5: Start Innovation 3 monitor ────────────────────────────────
        if self.enable_adaptive_rekey:
            self.monitor = AdaptiveRekeyMonitor(
                user_id=self.user_id,
                enrolled_embedding=self.enrolled_face_embedding,
                rekey_callback=self._on_rekey_triggered,
                get_live_embedding=self.get_live_embedding,
            )
            self.monitor.start()

        self._started = True

        return {
            'user_id': self.user_id,
            'key_fingerprint': self.aes.get_key_fingerprint(),
            'fusion_salt': self.fusion_salt.hex(),
            'biometric_seeded': bb84_result.biometric_seeded,
            'liveness_passed': bb84_result.liveness_passed,
            'qber': bb84_result.error_rate,
            'eavesdropping_detected': bb84_result.eavesdropping_detected,
        }

    # ── INNOVATION 3: Re-key callback ─────────────────────────────────────────

    def _on_rekey_triggered(self, user_id: str, similarity_score: float) -> None:
        """
        INNOVATION 3: Called by AdaptiveRekeyMonitor when re-key is needed.

        Performs a fresh BB84 run with current biometric seeds and updates
        the active AES key via AESCrypto.update_key().
        """
        logger.info(
            f"[Session] Re-key triggered — user='{user_id}', "
            f"similarity={similarity_score:.4f}"
        )

        face_seed = self.extractor.face_embedding_to_bytes(self.face_embedding)
        fp_seed = self.extractor.fingerprint_token_to_bytes(self.fingerprint_token)

        # Fresh BB84 round (no liveness update during mid-session re-key)
        new_bb84 = self.bb84.generate_key(
            face_embedding=face_seed,
            fingerprint_token=fp_seed,
            user_id=None,               # Skip liveness update for re-key events
            enable_liveness_check=False,
        )

        new_key, _ = self.fusion.fuse_keys(
            qkd_key=new_bb84.key,
            face_hash=face_seed,
            fingerprint_hash=fp_seed,
            salt=self.fusion_salt,
        )

        self.aes.update_key(
            new_key=new_key,
            reason=f"adaptive_rekey_similarity={similarity_score:.4f}",
        )

    # ── Convenience wrappers ───────────────────────────────────────────────────

    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Encrypt a file using the current (possibly rotated) AES key."""
        self._assert_started()
        return self.aes.encrypt_file(file_path, output_path)

    def decrypt_file(self, file_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt a file using the current AES key."""
        self._assert_started()
        return self.aes.decrypt_file(file_path, output_path)

    def stop(self) -> Dict[str, Any]:
        """Stop the session and return statistics."""
        if self.monitor:
            self.monitor.stop()

        stats = {
            'user_id': self.user_id,
            'aes_rekey_summary': self.aes.get_rekey_summary() if self.aes else None,
            'monitor_stats': self.monitor.get_session_stats() if self.monitor else None,
        }
        logger.info(f"[Session] Session ended — stats: {stats}")
        self._started = False
        return stats

    def _assert_started(self) -> None:
        if not self._started or not self.aes:
            raise RuntimeError("Session not started. Call start() first.")