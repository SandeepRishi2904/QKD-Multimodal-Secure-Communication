"""
Key Fusion Module — Enhanced with Innovations

INNOVATION 1 — Biometric Quantum Entropy Seeding (BQES):
    The face embedding vector and fingerprint token are converted to raw bytes
    and passed directly to bb84.py as entropy sources for basis selection.
    This module provides the biometric-to-bytes conversion layer so that the
    ArcFace 512-dim float32 embedding becomes a reproducible, stable byte
    sequence suitable for seeding the BB84 RNG.

INNOVATION 3 — Biometric-Confidence-Driven Adaptive Re-keying:
    During an active session, the cosine similarity score between the live
    face embedding and the enrolled template is continuously monitored.
    When the score drops below a configurable threshold, a full BB84 re-key
    cycle is triggered automatically — the encryption key rotates mid-session
    tied to live biometric confidence decay.
    High confidence → longer key lifetime.
    Drifting match → more frequent rotation → stronger forward secrecy.
"""

import os
import hashlib
import logging
import time
import threading
from typing import Optional, Tuple, Dict, Any, Callable, List
import numpy as np
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from config import HKDF_INFO, SALT_SIZE, AES_KEY_SIZE

logger = logging.getLogger(__name__)

# ── INNOVATION 3 thresholds ────────────────────────────────────────────────────
REKEY_SIMILARITY_THRESHOLD = 0.75   # Trigger re-key if cosine similarity drops below this
REKEY_COOLDOWN_SECONDS = 10         # Minimum seconds between consecutive re-keys
REKEY_CHECK_INTERVAL_SECONDS = 2    # How often to poll the live similarity score


class BiometricEntropyExtractor:
    """
    INNOVATION 1: Converts biometric data into stable byte sequences
    suitable for seeding the BB84 quantum basis RNG.

    ArcFace returns a 512-dimensional float32 vector.  Raw float bytes are
    platform-dependent and may vary slightly between calls due to numerical
    precision.  We normalise the vector, quantise to int16, and hash with
    SHA3-512 to produce a stable 64-byte seed.
    """

    @staticmethod
    def face_embedding_to_bytes(embedding: List[float]) -> bytes:
        """
        Convert an ArcFace 512-dim float embedding to a stable 64-byte seed.

        Steps:
            1. L2-normalise the vector (remove magnitude, keep direction).
            2. Quantise to int16 (×10000) for platform-independence.
            3. Hash with SHA3-512 → 64 bytes.

        Args:
            embedding: List or numpy array of 512 float32 values from DeepFace.

        Returns:
            64 stable bytes representing the embedding identity.
        """
        vec = np.array(embedding, dtype=np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        quantised = (vec * 10000).astype(np.int16)
        raw_bytes = quantised.tobytes()
        return hashlib.sha3_512(raw_bytes).digest()

    @staticmethod
    def fingerprint_token_to_bytes(token: Any) -> bytes:
        """
        Convert a fingerprint token (string/bytes/dict) to 64 stable bytes.

        Args:
            token: Fingerprint token from Windows Hello or FM220U driver.

        Returns:
            64 bytes representing the fingerprint identity.
        """
        if isinstance(token, bytes):
            raw = token
        elif isinstance(token, str):
            raw = token.encode('utf-8')
        else:
            raw = str(token).encode('utf-8')
        return hashlib.sha3_512(raw).digest()

    @staticmethod
    def cosine_similarity(a: List[float], b: List[float]) -> float:
        """
        Compute cosine similarity between two embedding vectors.
        Returns a value in [-1, 1]; 1 = identical direction.
        """
        va = np.array(a, dtype=np.float32)
        vb = np.array(b, dtype=np.float32)
        denom = np.linalg.norm(va) * np.linalg.norm(vb)
        if denom == 0:
            return 0.0
        return float(np.dot(va, vb) / denom)


class KeyFusion:
    """
    Fuses QKD key with biometric data (face + fingerprint) using HKDF.

    Formula:
        AES_Key = HKDF(
            input_material = QKD_Key || Face_Seed || Fingerprint_Seed,
            salt           = random_salt,
            info           = "QKD-Biometric-Fusion-v2",
            length         = 32 bytes
        )

    INNOVATION 1 change: face_hash and fingerprint_hash are now derived via
    BiometricEntropyExtractor, making them stable, normalised, and explicitly
    tied to the biometric identity rather than being ad-hoc SHA-256 hashes of
    arbitrary byte representations.
    """

    def __init__(self):
        self.salt_size = SALT_SIZE
        self.info = HKDF_INFO
        self.extractor = BiometricEntropyExtractor()

    # ── INNOVATION 1: Biometric-to-bytes helpers ───────────────────────────────

    def prepare_face_seed(self, face_embedding: List[float]) -> bytes:
        """
        INNOVATION 1: Convert ArcFace embedding to a stable 64-byte seed
        using normalisation + quantisation + SHA3-512.
        """
        seed = self.extractor.face_embedding_to_bytes(face_embedding)
        logger.debug(f"[BQES] Face seed prepared: {seed.hex()[:16]}...")
        return seed

    def prepare_fingerprint_seed(self, fingerprint_token: Any) -> bytes:
        """
        INNOVATION 1: Convert fingerprint token to a stable 64-byte seed.
        """
        seed = self.extractor.fingerprint_token_to_bytes(fingerprint_token)
        logger.debug(f"[BQES] Fingerprint seed prepared: {seed.hex()[:16]}...")
        return seed

    # ── Core key fusion ────────────────────────────────────────────────────────

    def fuse_keys(
        self,
        qkd_key: bytes,
        face_hash: Optional[bytes] = None,
        fingerprint_hash: Optional[bytes] = None,
        salt: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Fuse multiple key materials into a single AES-256 key via HKDF.

        Args:
            qkd_key:          QKD-generated key (32 bytes).
            face_hash:        Face identity seed (64 bytes from BQES extractor).
            fingerprint_hash: Fingerprint identity seed (64 bytes).
            salt:             Random salt (generated if None).

        Returns:
            (fused_key, salt)
        """
        if salt is None:
            salt = os.urandom(self.salt_size)

        input_material = qkd_key
        if face_hash:
            input_material += face_hash
            logger.debug("Added face seed to HKDF input")
        if fingerprint_hash:
            input_material += fingerprint_hash
            logger.debug("Added fingerprint seed to HKDF input")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            info=self.info,
            backend=default_backend()
        )
        fused_key = hkdf.derive(input_material)
        logger.info(f"[KeyFusion] Key fusion complete: {len(fused_key)} bytes, "
                    f"input_material={len(input_material)} bytes")
        return fused_key, salt

    def fuse_with_verification(
        self,
        qkd_key: bytes,
        face_auth_result: Tuple[bool, float, bytes],
        fingerprint_auth_result: Tuple[bool, float, bytes],
        require_both: bool = True,
    ) -> Dict[str, Any]:
        """
        Fuse keys with authentication verification gate.

        face_auth_result / fingerprint_auth_result:
            (verified: bool, confidence: float, hash: bytes)
            The hash should now be the BQES-style seed (64 bytes from
            BiometricEntropyExtractor) rather than an ad-hoc SHA-256 hash.
        """
        face_verified, face_confidence, face_hash = face_auth_result
        fp_verified, fp_confidence, fp_hash = fingerprint_auth_result

        if require_both:
            if not (face_verified and fp_verified):
                logger.error("[KeyFusion] Both biometrics required but not verified")
                return {
                    'success': False,
                    'error': 'Both face and fingerprint verification required',
                    'face_verified': face_verified,
                    'fingerprint_verified': fp_verified,
                    'face_confidence': face_confidence,
                    'fingerprint_confidence': fp_confidence,
                }
        else:
            if not (face_verified or fp_verified):
                logger.error("[KeyFusion] At least one biometric required but none verified")
                return {
                    'success': False,
                    'error': 'At least one biometric verification required',
                    'face_verified': face_verified,
                    'fingerprint_verified': fp_verified,
                }

        fused_key, salt = self.fuse_keys(
            qkd_key=qkd_key,
            face_hash=face_hash if face_verified else None,
            fingerprint_hash=fp_hash if fp_verified else None,
        )

        return {
            'success': True,
            'key': fused_key,
            'salt': salt,
            'face_verified': face_verified,
            'fingerprint_verified': fp_verified,
            'face_confidence': face_confidence,
            'fingerprint_confidence': fp_confidence,
            'key_fingerprint': hashlib.sha256(fused_key).hexdigest()[:16],
        }

    def regenerate_key(
        self,
        qkd_key: bytes,
        salt: bytes,
        face_hash: Optional[bytes] = None,
        fingerprint_hash: Optional[bytes] = None,
    ) -> bytes:
        """Regenerate same key with known salt (receiver side)."""
        return self.fuse_keys(qkd_key, face_hash, fingerprint_hash, salt)[0]

    @staticmethod
    def generate_shared_seed() -> bytes:
        """Generate shared seed for deterministic QKD."""
        return os.urandom(32)

    def verify_key_integrity(self, key1: bytes, key2: bytes) -> bool:
        return key1 == key2


# ── INNOVATION 3: Adaptive Re-keying Monitor ──────────────────────────────────

class AdaptiveRekeyMonitor:
    """
    INNOVATION 3 — Biometric-Confidence-Driven Adaptive Re-keying.

    Runs a background thread that continuously polls the live face similarity
    score. When the score drops below REKEY_SIMILARITY_THRESHOLD, it triggers
    a full BB84 re-key cycle by calling the provided rekey_callback.

    Security properties:
    - Keys rotate automatically as biometric confidence decays.
    - An attacker who somehow obtains the current key gains access only until
      the next re-key, which is bounded by biometric drift speed.
    - Provides continuous Perfect Forward Secrecy within a session.
    - Frequent small rotations are less disruptive than session termination.

    Usage:
        monitor = AdaptiveRekeyMonitor(
            user_id="alice",
            enrolled_embedding=enrolled_face_vec,
            rekey_callback=my_rekey_function,  # called when re-key triggered
            get_live_embedding=lambda: camera.get_current_embedding(),
        )
        monitor.start()
        # ... session runs ...
        monitor.stop()
    """

    def __init__(
        self,
        user_id: str,
        enrolled_embedding: List[float],
        rekey_callback: Callable[[str, float], None],
        get_live_embedding: Callable[[], Optional[List[float]]],
        similarity_threshold: float = REKEY_SIMILARITY_THRESHOLD,
        check_interval: float = REKEY_CHECK_INTERVAL_SECONDS,
        rekey_cooldown: float = REKEY_COOLDOWN_SECONDS,
    ):
        """
        Args:
            user_id:             Identifier for logging.
            enrolled_embedding:  Baseline ArcFace embedding from enrolment.
            rekey_callback:      Called with (user_id, similarity_score) when
                                 re-key is triggered. Should run BB84 + KeyFusion
                                 and update the active AES key.
            get_live_embedding:  Callable that returns the current live face
                                 embedding (from continuous camera feed).
            similarity_threshold: Re-key if cosine similarity drops below this.
            check_interval:      Seconds between similarity checks.
            rekey_cooldown:      Minimum seconds between consecutive re-keys.
        """
        self.user_id = user_id
        self.enrolled_embedding = enrolled_embedding
        self.rekey_callback = rekey_callback
        self.get_live_embedding = get_live_embedding
        self.similarity_threshold = similarity_threshold
        self.check_interval = check_interval
        self.rekey_cooldown = rekey_cooldown

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_rekey_time: float = 0.0
        self._rekey_count: int = 0

        self.extractor = BiometricEntropyExtractor()

        # History for monitoring/logging
        self.similarity_history: List[Tuple[float, float]] = []   # (timestamp, score)
        self.rekey_events: List[Tuple[float, float]] = []          # (timestamp, score)

    def start(self) -> None:
        """Start the background monitoring thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name=f"AdaptiveRekey-{self.user_id}",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"[Innovation3] Adaptive re-key monitor started for '{self.user_id}' "
                    f"(threshold={self.similarity_threshold}, interval={self.check_interval}s)")

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(f"[Innovation3] Monitor stopped. Total re-keys: {self._rekey_count}")

    def _monitor_loop(self) -> None:
        """Background loop: poll similarity, trigger re-key when needed."""
        while not self._stop_event.is_set():
            try:
                live_embedding = self.get_live_embedding()
                if live_embedding is not None:
                    similarity = self.extractor.cosine_similarity(
                        self.enrolled_embedding, live_embedding
                    )
                    timestamp = time.time()
                    self.similarity_history.append((timestamp, similarity))

                    logger.debug(f"[Innovation3] '{self.user_id}' live similarity={similarity:.4f}")

                    if similarity < self.similarity_threshold:
                        cooldown_elapsed = (timestamp - self._last_rekey_time) >= self.rekey_cooldown
                        if cooldown_elapsed:
                            self._trigger_rekey(similarity)
                        else:
                            logger.debug(
                                f"[Innovation3] Re-key suppressed (cooldown: "
                                f"{self.rekey_cooldown - (timestamp - self._last_rekey_time):.1f}s remaining)"
                            )
            except Exception as e:
                logger.error(f"[Innovation3] Monitor error: {e}")

            self._stop_event.wait(timeout=self.check_interval)

    def _trigger_rekey(self, similarity_score: float) -> None:
        """
        Trigger a full BB84 re-key cycle.

        Calls the provided rekey_callback which is expected to:
        1. Run a fresh BB84 key generation (with BQES if biometrics available).
        2. Fuse the new QKD key with current biometrics via KeyFusion.
        3. Update the AES cipher in the active communication session.
        """
        self._rekey_count += 1
        self._last_rekey_time = time.time()
        self.rekey_events.append((self._last_rekey_time, similarity_score))

        logger.warning(
            f"[Innovation3] RE-KEY #{self._rekey_count} triggered for '{self.user_id}' "
            f"— cosine similarity={similarity_score:.4f} < threshold={self.similarity_threshold}"
        )

        try:
            self.rekey_callback(self.user_id, similarity_score)
            logger.info(f"[Innovation3] Re-key #{self._rekey_count} completed successfully")
        except Exception as e:
            logger.error(f"[Innovation3] Re-key callback failed: {e}")

    def get_session_stats(self) -> Dict[str, Any]:
        """Return session-level re-keying statistics."""
        scores = [s for _, s in self.similarity_history]
        return {
            'user_id': self.user_id,
            'total_rekeys': self._rekey_count,
            'rekey_events': self.rekey_events,
            'mean_similarity': float(np.mean(scores)) if scores else None,
            'min_similarity': float(np.min(scores)) if scores else None,
            'similarity_samples': len(scores),
        }


# ── Deterministic variant (backward compatibility) ────────────────────────────

class DeterministicKeyFusion(KeyFusion):
    """
    Deterministic key fusion for synchronized sender/receiver using a shared seed.
    INNOVATION 1: When raw embeddings are provided, BQES-style seeds are used
    instead of arbitrary SHA-256 hashes of biometric bytes.
    """

    def __init__(self, shared_seed: bytes):
        super().__init__()
        self.shared_seed = shared_seed

    def generate_deterministic_fusion(
        self,
        qkd_key: bytes,
        face_embedding: Optional[List[float]] = None,
        fingerprint_token: Optional[Any] = None,
    ) -> bytes:
        """
        Generate deterministic fused key.
        Uses BQES-style seeds when embeddings are provided.
        """
        face_seed = self.prepare_face_seed(face_embedding) if face_embedding else None
        fp_seed = self.prepare_fingerprint_seed(fingerprint_token) if fingerprint_token else None

        return self.fuse_keys(qkd_key, face_seed, fp_seed, self.shared_seed)[0]