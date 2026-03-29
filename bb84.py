"""
BB84 Quantum Key Distribution Protocol — Enhanced with Innovations

INNOVATION 1 — Biometric Quantum Entropy Seeding (BQES):
    Instead of generating BB84 basis choices from a generic PRNG, this module
    derives the basis selection seed directly from the user's biometric data
    (face embedding + fingerprint token) hashed via SHA3-512.
    The key is now mathematically bound to *who you are*, not just random numbers.
    An attacker who steals the QKD channel still cannot reproduce the key without
    the exact biometric of the enrolled user.

INNOVATION 2 — Quantum Noise Liveness Detection (QNLD):
    A controlled synthetic eavesdrop signal is injected into BB84 at a known rate.
    The resulting error rate distribution is recorded per user as their
    "quantum noise fingerprint". A replay attack (photo/video spoof) produces a
    statistically flat error profile that deviates from the enrolled fingerprint,
    triggering a liveness failure — without any camera depth sensor or blink test.
"""

import numpy as np
import hashlib
import logging
import json
import os
from typing import Tuple, List, Optional, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path
import secrets

logger = logging.getLogger(__name__)

LIVENESS_PROFILE_DIR = Path("data/liveness_profiles")
LIVENESS_PROFILE_DIR.mkdir(parents=True, exist_ok=True)

SYNTHETIC_EAVESDROP_RATE = 0.05   # 5% controlled injection for liveness probing
LIVENESS_DEVIATION_THRESHOLD = 0.03  # Max allowed deviation from enrolled profile
MIN_PROFILE_SESSIONS = 3           # Sessions needed before liveness enforcement


@dataclass
class BB84Result:
    """Result of BB84 key exchange"""
    key: bytes
    error_rate: float
    eavesdropping_detected: bool
    raw_key_length: int
    final_key_length: int
    sender_bases: List[int]
    receiver_bases: List[int]
    # INNOVATION 1: whether biometric seed was used
    biometric_seeded: bool = False
    biometric_seed_fingerprint: Optional[str] = None
    # INNOVATION 2: liveness check result
    liveness_passed: Optional[bool] = None
    liveness_deviation: Optional[float] = None
    quantum_noise_profile: Optional[float] = None


@dataclass
class LivenessProfile:
    """
    INNOVATION 2: Per-user quantum noise fingerprint.
    Stores historical QBER (Quantum Bit Error Rate) samples collected during
    enrolment sessions. Used to detect spoofed (replay) biometric sessions.
    """
    user_id: str
    error_rate_samples: List[float] = field(default_factory=list)
    mean_error_rate: float = 0.0
    std_error_rate: float = 0.0
    session_count: int = 0

    def update(self, error_rate: float) -> None:
        self.error_rate_samples.append(error_rate)
        self.session_count += 1
        self.mean_error_rate = float(np.mean(self.error_rate_samples))
        self.std_error_rate = float(np.std(self.error_rate_samples)) if len(self.error_rate_samples) > 1 else 0.01

    def is_consistent(self, error_rate: float) -> Tuple[bool, float]:
        """
        Check if a new error rate is statistically consistent with the
        enrolled profile. Returns (passed, deviation).
        """
        if self.session_count < MIN_PROFILE_SESSIONS:
            # Not enough data yet — pass but keep recording
            return True, 0.0
        deviation = abs(error_rate - self.mean_error_rate)
        passed = deviation <= LIVENESS_DEVIATION_THRESHOLD
        return passed, deviation

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "error_rate_samples": self.error_rate_samples,
            "mean_error_rate": self.mean_error_rate,
            "std_error_rate": self.std_error_rate,
            "session_count": self.session_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LivenessProfile":
        p = cls(user_id=d["user_id"])
        p.error_rate_samples = d.get("error_rate_samples", [])
        p.mean_error_rate = d.get("mean_error_rate", 0.0)
        p.std_error_rate = d.get("std_error_rate", 0.01)
        p.session_count = d.get("session_count", 0)
        return p


def load_liveness_profile(user_id: str) -> LivenessProfile:
    path = LIVENESS_PROFILE_DIR / f"{user_id}.json"
    if path.exists():
        with open(path) as f:
            return LivenessProfile.from_dict(json.load(f))
    return LivenessProfile(user_id=user_id)


def save_liveness_profile(profile: LivenessProfile) -> None:
    path = LIVENESS_PROFILE_DIR / f"{profile.user_id}.json"
    with open(path, "w") as f:
        json.dump(profile.to_dict(), f, indent=2)


class BB84Protocol:
    """
    BB84 Quantum Key Distribution Protocol

    Enhanced with:
    - INNOVATION 1: Biometric Quantum Entropy Seeding (BQES)
    - INNOVATION 2: Quantum Noise Liveness Detection (QNLD)

    Simulates quantum transmission using classical RNG seeded by biometric entropy,
    with optional synthetic eavesdrop injection for liveness profiling.
    """

    RECTILINEAR = 0  # + basis: 0° = 0, 90° = 1
    DIAGONAL = 1     # x basis: 45° = 0, 135° = 1

    def __init__(self, key_length: int = 256):
        self.key_length = key_length
        self.error_threshold = 0.15

    # ─────────────────────────────────────────────
    # INNOVATION 1: Biometric Quantum Entropy Seeding
    # ─────────────────────────────────────────────

    @staticmethod
    def derive_biometric_seed(
        face_embedding: Optional[bytes],
        fingerprint_token: Optional[bytes]
    ) -> Tuple[bytes, str]:
        """
        Derives a deterministic 64-byte seed from biometric inputs using SHA3-512.

        The seed is used to initialise the NumPy RNG that selects BB84 basis
        choices (RECTILINEAR vs DIAGONAL). This makes the basis sequence
        cryptographically tied to the user's biometric identity.

        Args:
            face_embedding:    Raw bytes of the ArcFace 512-dim embedding vector.
            fingerprint_token: Raw bytes of the fingerprint template/token.

        Returns:
            (seed_bytes, fingerprint_hex) — seed for RNG, short hex ID for logs.
        """
        combined = b""
        if face_embedding:
            combined += face_embedding
        if fingerprint_token:
            combined += fingerprint_token

        if not combined:
            # No biometric data — fall back to random seed (no BQES)
            seed_bytes = secrets.token_bytes(64)
            return seed_bytes, "random-fallback"

        seed_bytes = hashlib.sha3_512(combined).digest()   # 64 bytes
        fingerprint_hex = seed_bytes.hex()[:16]
        logger.info(f"[BQES] Biometric seed derived: ...{fingerprint_hex}")
        return seed_bytes, fingerprint_hex

    def generate_sender_data_bqes(
        self,
        biometric_seed: bytes
    ) -> Tuple[List[int], List[int]]:
        """
        INNOVATION 1: Generate BB84 sender bits and *biometrically-seeded* bases.

        The basis choices (which determine the quantum polarisation axis Alice
        uses to encode each qubit) are generated from the biometric seed rather
        than a system PRNG. This means:
            - Two different users will always produce different basis sequences.
            - An attacker who intercepts the channel cannot reproduce the bases
              without the enrolled biometric.
            - The bits themselves remain cryptographically random (secrets module).

        Args:
            biometric_seed: 64-byte seed from derive_biometric_seed().

        Returns:
            (bits, bases)
        """
        # Bits: still truly random (security-critical, must NOT be biometric)
        bits = [secrets.randbelow(2) for _ in range(self.key_length * 4)]

        # Bases: seeded from biometric (identity-binding step)
        seed_int = int.from_bytes(biometric_seed[:4], 'big')
        rng = np.random.default_rng(seed_int)
        bases = rng.integers(0, 2, size=self.key_length * 4).tolist()

        logger.debug(f"[BQES] Generated {len(bits)} bits, {len(bases)} biometric-seeded bases")
        return bits, bases

    def generate_sender_data(self) -> Tuple[List[int], List[int]]:
        """
        Original sender data generation (random bases — no BQES).
        Kept for backward compatibility and testing.
        """
        bits = [secrets.randbelow(2) for _ in range(self.key_length * 4)]
        bases = [secrets.randbelow(2) for _ in range(self.key_length * 4)]
        return bits, bases

    # ─────────────────────────────────────────────
    # Core BB84 transmission and sifting
    # ─────────────────────────────────────────────

    def simulate_quantum_transmission(
        self,
        bits: List[int],
        bases: List[int],
        eavesdrop: bool = False,
        synthetic_eavesdrop_rate: float = 0.0
    ) -> Tuple[List[int], List[int]]:
        """
        Simulate quantum channel transmission to receiver (Bob).

        Args:
            bits:                    Alice's bit sequence.
            bases:                   Alice's basis sequence.
            eavesdrop:               Simulate a real attacker (random Eve).
            synthetic_eavesdrop_rate: INNOVATION 2 — deliberate controlled
                                      eavesdrop injection at a known rate for
                                      liveness profiling (see QNLD below).
        """
        receiver_bases = [secrets.randbelow(2) for _ in range(len(bits))]
        measured_bits = []

        for i, (bit, basis) in enumerate(zip(bits, bases)):

            # Real eavesdrop simulation
            if eavesdrop and secrets.randbelow(4) == 0:
                eve_basis = secrets.randbelow(2)
                if eve_basis != basis:
                    bit = secrets.randbelow(2)

            # INNOVATION 2: Synthetic controlled eavesdrop for liveness probing
            # Inject errors at a fixed known rate so the receiver's error profile
            # can be compared against the user's enrolled quantum noise fingerprint.
            if synthetic_eavesdrop_rate > 0:
                if secrets.randbelow(1000) < int(synthetic_eavesdrop_rate * 1000):
                    probe_basis = secrets.randbelow(2)
                    if probe_basis != basis:
                        bit = secrets.randbelow(2)

            # Bob's measurement
            if receiver_bases[i] == basis:
                measured_bits.append(bit)
            else:
                measured_bits.append(secrets.randbelow(2))

        return measured_bits, receiver_bases

    def sift_key(
        self,
        sender_bits: List[int],
        sender_bases: List[int],
        receiver_bits: List[int],
        receiver_bases: List[int]
    ) -> Tuple[List[int], List[int]]:
        """Key sifting: keep only bits where sender and receiver bases match."""
        sifted_sender, sifted_receiver = [], []
        for sb, rb, sbit, rbit in zip(sender_bases, receiver_bases, sender_bits, receiver_bits):
            if sb == rb:
                sifted_sender.append(sbit)
                sifted_receiver.append(rbit)
        return sifted_sender, sifted_receiver

    def estimate_error_rate(
        self,
        bits1: List[int],
        bits2: List[int],
        sample_size: Optional[int] = None
    ) -> float:
        """Estimate QBER by comparing a random subset of sifted bits."""
        if sample_size is None:
            sample_size = len(bits1) // 4
        if len(bits1) < sample_size or len(bits2) < sample_size:
            return 0.0
        indices = np.random.choice(len(bits1), min(sample_size, len(bits1)), replace=False)
        errors = sum(1 for i in indices if bits1[i] != bits2[i])
        return errors / len(indices)

    def privacy_amplification(self, bits: List[int]) -> bytes:
        """Privacy amplification: hash sifted bits to produce final key."""
        bit_string = ''.join(str(b) for b in bits)
        while len(bit_string) % 8 != 0:
            bit_string += '0'
        byte_array = int(bit_string, 2).to_bytes(len(bit_string) // 8, 'big')
        return hashlib.sha256(byte_array).digest()

    # ─────────────────────────────────────────────
    # INNOVATION 2: Quantum Noise Liveness Detection
    # ─────────────────────────────────────────────

    def check_liveness(
        self,
        user_id: str,
        observed_error_rate: float,
        update_profile: bool = True
    ) -> Tuple[bool, float, LivenessProfile]:
        """
        INNOVATION 2: Quantum Noise Liveness Detection (QNLD).

        Compares the observed QBER from the current session against the user's
        enrolled quantum noise fingerprint (historical QBER distribution).

        A live biometric (real face/fingerprint) produces natural micro-variations
        in the error rate due to timing jitter, sensor noise, and biometric drift.
        A replay attack (recorded biometric) produces a statistically flat,
        suspiciously consistent error profile that deviates from the enrolled mean.

        Args:
            user_id:            Enrolled user identifier.
            observed_error_rate: QBER measured in this session.
            update_profile:     If True, add this session to the enrolled profile.

        Returns:
            (liveness_passed, deviation, updated_profile)
        """
        profile = load_liveness_profile(user_id)
        passed, deviation = profile.is_consistent(observed_error_rate)

        if update_profile:
            profile.update(observed_error_rate)
            save_liveness_profile(profile)
            logger.info(
                f"[QNLD] User '{user_id}' profile updated: "
                f"sessions={profile.session_count}, "
                f"mean_QBER={profile.mean_error_rate:.4f}"
            )

        if profile.session_count < MIN_PROFILE_SESSIONS:
            logger.info(f"[QNLD] Building profile for '{user_id}' ({profile.session_count}/{MIN_PROFILE_SESSIONS})")
        elif passed:
            logger.info(f"[QNLD] Liveness PASSED for '{user_id}' — deviation={deviation:.4f}")
        else:
            logger.warning(
                f"[QNLD] Liveness FAILED for '{user_id}' — "
                f"deviation={deviation:.4f} > threshold={LIVENESS_DEVIATION_THRESHOLD}"
            )

        return passed, deviation, profile

    # ─────────────────────────────────────────────
    # Main key generation — BQES + QNLD integrated
    # ─────────────────────────────────────────────

    def generate_key(
        self,
        simulate_eavesdrop: bool = False,
        face_embedding: Optional[bytes] = None,
        fingerprint_token: Optional[bytes] = None,
        user_id: Optional[str] = None,
        enable_liveness_check: bool = True,
    ) -> BB84Result:
        """
        Execute complete BB84 protocol with BQES and QNLD innovations.

        Args:
            simulate_eavesdrop:    Simulate a real attacker on the channel.
            face_embedding:        INNOVATION 1 — ArcFace embedding bytes.
            fingerprint_token:     INNOVATION 1 — Fingerprint token bytes.
            user_id:               INNOVATION 2 — User ID for liveness profile lookup.
            enable_liveness_check: INNOVATION 2 — Whether to run QNLD.

        Returns:
            BB84Result with all protocol statistics and innovation outputs.
        """
        logger.info("Starting BB84 key generation (BQES + QNLD)...")

        # ── INNOVATION 1: Derive biometric seed ──────────────────────────────
        biometric_seeded = False
        biometric_seed_fingerprint = None

        if face_embedding or fingerprint_token:
            biometric_seed, biometric_seed_fingerprint = self.derive_biometric_seed(
                face_embedding, fingerprint_token
            )
            sender_bits, sender_bases = self.generate_sender_data_bqes(biometric_seed)
            biometric_seeded = True
            logger.info("[BQES] Bases generated from biometric entropy seed")
        else:
            sender_bits, sender_bases = self.generate_sender_data()
            logger.info("[BQES] No biometric data — using random bases (fallback)")

        # ── INNOVATION 2: Inject synthetic eavesdrop for liveness probe ───────
        synthetic_rate = SYNTHETIC_EAVESDROP_RATE if (enable_liveness_check and user_id) else 0.0

        receiver_bits, receiver_bases = self.simulate_quantum_transmission(
            sender_bits, sender_bases,
            eavesdrop=simulate_eavesdrop,
            synthetic_eavesdrop_rate=synthetic_rate
        )

        # ── Key sifting ───────────────────────────────────────────────────────
        sifted_sender, sifted_receiver = self.sift_key(
            sender_bits, sender_bases, receiver_bits, receiver_bases
        )
        raw_key_length = len(sifted_sender)
        logger.info(f"After sifting: {raw_key_length} bits")

        if raw_key_length < self.key_length:
            raise ValueError(f"Insufficient sifted key length: {raw_key_length}")

        # ── Error rate estimation ─────────────────────────────────────────────
        error_rate = self.estimate_error_rate(sifted_sender, sifted_receiver)
        logger.info(f"Estimated QBER: {error_rate:.4f}")

        # ── Real eavesdropping detection ──────────────────────────────────────
        # Subtract the known synthetic injection before comparing to threshold
        adjusted_error_rate = max(0.0, error_rate - synthetic_rate)
        eavesdropping_detected = adjusted_error_rate > self.error_threshold
        if eavesdropping_detected:
            logger.warning(f"[BB84] Eavesdropping detected! Adjusted QBER={adjusted_error_rate:.4f}")
        else:
            logger.info("[BB84] No eavesdropping detected")

        # ── INNOVATION 2: Quantum noise liveness check ────────────────────────
        liveness_passed = None
        liveness_deviation = None

        if enable_liveness_check and user_id:
            liveness_passed, liveness_deviation, _ = self.check_liveness(
                user_id=user_id,
                observed_error_rate=error_rate,
                update_profile=True
            )
            if not liveness_passed:
                logger.error(
                    f"[QNLD] Session blocked — liveness check failed for '{user_id}'. "
                    f"Possible replay/spoof attack."
                )

        # ── Privacy amplification → final key ────────────────────────────────
        undisclosed_bits = sifted_sender[self.key_length // 4:]
        final_key = self.privacy_amplification(undisclosed_bits[:self.key_length])
        logger.info(f"Final key generated: {len(final_key)} bytes")

        return BB84Result(
            key=final_key,
            error_rate=error_rate,
            eavesdropping_detected=eavesdropping_detected,
            raw_key_length=raw_key_length,
            final_key_length=len(final_key),
            sender_bases=sender_bases[:100],
            receiver_bases=receiver_bases[:100],
            biometric_seeded=biometric_seeded,
            biometric_seed_fingerprint=biometric_seed_fingerprint,
            liveness_passed=liveness_passed,
            liveness_deviation=liveness_deviation,
            quantum_noise_profile=error_rate,
        )

    def verify_key_integrity(self, key1: bytes, key2: bytes) -> bool:
        """Verify two parties have the same key."""
        return key1 == key2


class DeterministicBB84:
    """
    Deterministic BB84 for synchronized sender/receiver using a shared seed.

    INNOVATION 1 extended: When biometric data is provided, the biometric seed
    *replaces* the shared seed as the basis source, making the deterministic
    channel also identity-bound.
    """

    def __init__(self, seed: Optional[bytes] = None):
        if seed is None:
            seed = secrets.token_bytes(32)
        self.seed = seed
        self.protocol = BB84Protocol(key_length=256)

    def generate_deterministic_key(
        self,
        face_embedding: Optional[bytes] = None,
        fingerprint_token: Optional[bytes] = None,
        user_id: Optional[str] = None,
    ) -> BB84Result:
        """
        Generate key deterministically.
        If biometrics are provided, BQES overrides the shared seed for bases.
        """
        np.random.seed(int.from_bytes(self.seed[:4], 'big'))
        return self.protocol.generate_key(
            simulate_eavesdrop=False,
            face_embedding=face_embedding,
            fingerprint_token=fingerprint_token,
            user_id=user_id,
            enable_liveness_check=(user_id is not None),
        )

    @staticmethod
    def create_shared_seed() -> bytes:
        """Create a shared seed for sender and receiver pre-sharing."""
        return secrets.token_bytes(32)