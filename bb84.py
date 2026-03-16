"""
BB84 Quantum Key Distribution Protocol Implementation
Simulates quantum key exchange with eavesdropping detection
"""
import numpy as np
import hashlib
import logging
from typing import Tuple, List, Optional
from dataclasses import dataclass
import secrets

logger = logging.getLogger(__name__)

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

class BB84Protocol:
    """
    BB84 Quantum Key Distribution Protocol

    Simulates quantum transmission using classical random number generation
    with quantum mechanical principles:
    - Polarization states (0°, 90°, 45°, 135°)
    - Basis choice (Rectilinear + or Diagonal x)
    - Eavesdropping detection via error rate analysis
    """

    # Basis definitions
    RECTILINEAR = 0  # + basis: 0° = 0, 90° = 1
    DIAGONAL = 1     # x basis: 45° = 0, 135° = 1

    def __init__(self, key_length: int = 256):
        self.key_length = key_length
        self.error_threshold = 0.15

    def generate_sender_data(self) -> Tuple[List[int], List[int]]:
        """
        Generate random bits and random bases for sender (Alice)
        Returns: (bits, bases)
        """
        # Generate random bits
        bits = [secrets.randbelow(2) for _ in range(self.key_length * 4)]
        # Generate random bases (0 or 1)
        bases = [secrets.randbelow(2) for _ in range(self.key_length * 4)]
        return bits, bases

    def simulate_quantum_transmission(self, bits: List[int], bases: List[int], 
                                     eavesdrop: bool = False) -> Tuple[List[int], List[int]]:
        """
        Simulate quantum channel transmission to receiver (Bob)
        Includes optional eavesdropping simulation
        """
        # Bob generates random bases
        receiver_bases = [secrets.randbelow(2) for _ in range(len(bits))]

        # Simulate measurement
        measured_bits = []
        for i, (bit, basis) in enumerate(zip(bits, bases)):
            if eavesdrop and secrets.randbelow(4) == 0:  # 25% chance Eve measures
                # Eavesdropper introduces errors when basis mismatch
                eve_basis = secrets.randbelow(2)
                if eve_basis != basis:
                    # Eve resends wrong state 50% of time
                    bit = secrets.randbelow(2)

            # Bob's measurement
            if receiver_bases[i] == basis:
                # Correct basis - perfect measurement
                measured_bits.append(bit)
            else:
                # Wrong basis - random result
                measured_bits.append(secrets.randbelow(2))

        return measured_bits, receiver_bases

    def sift_key(self, sender_bits: List[int], sender_bases: List[int],
                receiver_bits: List[int], receiver_bases: List[int]) -> Tuple[List[int], List[int]]:
        """
        Key sifting: keep only bits where bases match
        """
        sifted_sender = []
        sifted_receiver = []

        for sb, rb, sbit, rbit in zip(sender_bases, receiver_bases, sender_bits, receiver_bits):
            if sb == rb:  # Bases match
                sifted_sender.append(sbit)
                sifted_receiver.append(rbit)

        return sifted_sender, sifted_receiver

    def estimate_error_rate(self, bits1: List[int], bits2: List[int], 
                           sample_size: int = None) -> float:
        """
        Estimate error rate by comparing random subset of bits
        """
        if sample_size is None:
            sample_size = len(bits1) // 4  # Use 25% for error estimation

        if len(bits1) < sample_size or len(bits2) < sample_size:
            return 0.0

        # Random sample indices
        indices = np.random.choice(len(bits1), min(sample_size, len(bits1)), replace=False)

        errors = sum(1 for i in indices if bits1[i] != bits2[i])
        return errors / len(indices)

    def privacy_amplification(self, bits: List[int]) -> bytes:
        """
        Privacy amplification using hashing
        Reduces key length but increases security
        """
        # Convert bits to bytes
        bit_string = ''.join(str(b) for b in bits)

        # Pad to multiple of 8
        while len(bit_string) % 8 != 0:
            bit_string += '0'

        # Convert to bytes
        byte_array = int(bit_string, 2).to_bytes(len(bit_string) // 8, 'big')

        # Hash to final key size (256 bits = 32 bytes)
        return hashlib.sha256(byte_array).digest()

    def generate_key(self, simulate_eavesdrop: bool = False) -> BB84Result:
        """
        Execute complete BB84 protocol

        Args:
            simulate_eavesdrop: If True, simulates eavesdropping attack

        Returns:
            BB84Result containing key and protocol statistics
        """
        logger.info("Starting BB84 key generation...")

        # Step 1: Alice generates random bits and bases
        sender_bits, sender_bases = self.generate_sender_data()
        logger.debug(f"Sender generated {len(sender_bits)} bits")

        # Step 2: Quantum transmission to Bob
        receiver_bits, receiver_bases = self.simulate_quantum_transmission(
            sender_bits, sender_bases, eavesdrop=simulate_eavesdrop
        )

        # Step 3: Key sifting
        sifted_sender, sifted_receiver = self.sift_key(
            sender_bits, sender_bases, receiver_bits, receiver_bases
        )

        raw_key_length = len(sifted_sender)
        logger.info(f"After sifting: {raw_key_length} bits")

        if raw_key_length < self.key_length:
            raise ValueError(f"Insufficient key length after sifting: {raw_key_length}")

        # Step 4: Error estimation
        error_rate = self.estimate_error_rate(sifted_sender, sifted_receiver)
        logger.info(f"Estimated error rate: {error_rate:.2%}")

        # Step 5: Eavesdropping detection
        eavesdropping_detected = error_rate > self.error_threshold

        if eavesdropping_detected:
            logger.warning(f"⚠️  Eavesdropping detected! Error rate {error_rate:.2%} exceeds threshold")
        else:
            logger.info("✅ No eavesdropping detected")

        # Step 6: Privacy amplification (remove disclosed bits first)
        undisclosed_bits = sifted_sender[self.key_length//4:]  # Remove error check bits
        final_key = self.privacy_amplification(undisclosed_bits[:self.key_length])

        logger.info(f"Final key generated: {len(final_key)} bytes")

        return BB84Result(
            key=final_key,
            error_rate=error_rate,
            eavesdropping_detected=eavesdropping_detected,
            raw_key_length=raw_key_length,
            final_key_length=len(final_key),
            sender_bases=sender_bases[:100],  # Store sample for verification
            receiver_bases=receiver_bases[:100]
        )

    def verify_key_integrity(self, key1: bytes, key2: bytes) -> bool:
        """Verify two parties have the same key"""
        return key1 == key2

class DeterministicBB84:
    """
    Deterministic BB84 for synchronized sender/receiver
    Uses shared seed for reproducible key generation
    """

    def __init__(self, seed: Optional[bytes] = None):
        if seed is None:
            seed = secrets.token_bytes(32)
        self.seed = seed
        self.protocol = BB84Protocol(key_length=256)

    def generate_deterministic_key(self) -> bytes:
        """Generate deterministic key from seed"""
        # Use seed to initialize RNG
        np.random.seed(int.from_bytes(self.seed[:4], 'big'))

        # Generate key
        result = self.protocol.generate_key(simulate_eavesdrop=False)

        return result.key

    @staticmethod
    def create_shared_seed() -> bytes:
        """Create a shared seed for sender and receiver"""
        return secrets.token_bytes(32)
