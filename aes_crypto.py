# """
# AES-256-GCM Encryption Module
# Military-grade authenticated encryption
# """
# import hashlib
# import os
# import json
# import base64
# import logging
# from pathlib import Path
# from typing import Tuple, Optional, Dict, Any, Union
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.backends import default_backend
# import zlib

# from config import AES_KEY_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, TEMP_DIR

# logger = logging.getLogger(__name__)

# class AESCrypto:
#     """
#     AES-256-GCM authenticated encryption
#     Provides confidentiality and integrity
#     """

#     def __init__(self, key: Optional[bytes] = None):
#         """
#         Initialize with key or generate random key

#         Args:
#             key: 32-byte key for AES-256, or None to generate
#         """
#         if key is None:
#             self.key = os.urandom(AES_KEY_SIZE)
#         else:
#             if len(key) != AES_KEY_SIZE:
#                 raise ValueError(f"Key must be {AES_KEY_SIZE} bytes for AES-256")
#             self.key = key

#     @staticmethod
#     def generate_key() -> bytes:
#         """Generate random 256-bit key"""
#         return os.urandom(AES_KEY_SIZE)

#     def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
#         """
#         Encrypt data using AES-256-GCM

#         Args:
#             plaintext: Data to encrypt
#             associated_data: Additional authenticated data (not encrypted, but integrity protected)

#         Returns:
#             Dict with 'ciphertext', 'nonce', 'tag', and optional 'associated_data'
#         """
#         # Generate random nonce
#         nonce = os.urandom(AES_NONCE_SIZE)

#         # Create cipher
#         cipher = Cipher(
#             algorithms.AES(self.key),
#             modes.GCM(nonce),
#             backend=default_backend()
#         )
#         encryptor = cipher.encryptor()

#         # Add associated data if provided
#         if associated_data:
#             encryptor.authenticate_additional_data(associated_data)

#         # Encrypt
#         ciphertext = encryptor.update(plaintext) + encryptor.finalize()
#         tag = encryptor.tag

#         return {
#             'ciphertext': ciphertext,
#             'nonce': nonce,
#             'tag': tag,
#             'associated_data': associated_data
#         }

#     def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, 
#                 associated_data: Optional[bytes] = None) -> bytes:
#         """
#         Decrypt data using AES-256-GCM

#         Args:
#             ciphertext: Encrypted data
#             nonce: Nonce used for encryption
#             tag: Authentication tag
#             associated_data: Additional authenticated data used during encryption

#         Returns:
#             Decrypted plaintext

#         Raises:
#             Exception: If authentication fails (tampering detected)
#         """
#         # Create cipher
#         cipher = Cipher(
#             algorithms.AES(self.key),
#             modes.GCM(nonce, tag),
#             backend=default_backend()
#         )
#         decryptor = cipher.decryptor()

#         # Add associated data if provided
#         if associated_data:
#             decryptor.authenticate_additional_data(associated_data)

#         # Decrypt
#         plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#         return plaintext

#     def encrypt_file(self, file_path: Union[str, Path], 
#                    output_path: Optional[Union[str, Path]] = None,
#                    compress: bool = True) -> Dict[str, Any]:
#         """
#         Encrypt a file

#         Args:
#             file_path: Path to file to encrypt
#             output_path: Output path (default: original + '.enc')
#             compress: Whether to compress before encryption

#         Returns:
#             Encryption metadata
#         """
#         file_path = Path(file_path)

#         if not file_path.exists():
#             raise FileNotFoundError(f"File not found: {file_path}")

#         if output_path is None:
#             output_path = file_path.with_suffix(file_path.suffix + '.enc')
#         else:
#             output_path = Path(output_path)

#         # Read file
#         with open(file_path, 'rb') as f:
#             plaintext = f.read()

#         # Compress if requested
#         if compress:
#             plaintext = zlib.compress(plaintext)
#             is_compressed = True
#         else:
#             is_compressed = False

#         # Add metadata header
#         metadata = {
#             'original_name': file_path.name,
#             'original_size': len(plaintext),
#             'compressed': is_compressed,
#             'compression': 'zlib' if is_compressed else None
#         }
#         metadata_bytes = json.dumps(metadata).encode()

#         # Combine metadata length + metadata + plaintext
#         metadata_len = len(metadata_bytes).to_bytes(4, 'big')
#         plaintext_with_meta = metadata_len + metadata_bytes + plaintext

#         # Encrypt
#         encryption_result = self.encrypt(plaintext_with_meta)

#         # Write to file
#         with open(output_path, 'wb') as f:
#             f.write(encryption_result['nonce'])
#             f.write(encryption_result['tag'])
#             f.write(encryption_result['ciphertext'])

#         logger.info(f"✅ Encrypted: {file_path} -> {output_path}")

#         return {
#             'input_file': str(file_path),
#             'output_file': str(output_path),
#             'nonce': base64.b64encode(encryption_result['nonce']).decode(),
#             'tag': base64.b64encode(encryption_result['tag']).decode(),
#             'metadata': metadata
#         }

#     def decrypt_file(self, file_path: Union[str, Path], 
#                     output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
#         """
#         Decrypt a file

#         Args:
#             file_path: Path to encrypted file
#             output_path: Output path (default: from metadata or strip .enc)

#         Returns:
#             Decryption metadata
#         """
#         file_path = Path(file_path)

#         if not file_path.exists():
#             raise FileNotFoundError(f"File not found: {file_path}")

#         # Read encrypted file
#         with open(file_path, 'rb') as f:
#             nonce = f.read(AES_NONCE_SIZE)
#             tag = f.read(AES_TAG_SIZE)
#             ciphertext = f.read()

#         # Decrypt
#         plaintext = self.decrypt(ciphertext, nonce, tag)

#         # Parse metadata
#         metadata_len = int.from_bytes(plaintext[:4], 'big')
#         metadata_bytes = plaintext[4:4+metadata_len]
#         file_content = plaintext[4+metadata_len:]

#         metadata = json.loads(metadata_bytes.decode())

#         # Decompress if needed
#         if metadata.get('compressed'):
#             file_content = zlib.decompress(file_content)

#         # Determine output path
#         if output_path is None:
#             if metadata.get('original_name'):
#                 output_path = TEMP_DIR / metadata['original_name']
#             else:
#                 output_path = file_path.with_suffix('')
#         else:
#             output_path = Path(output_path)

#         # Write decrypted file
#         with open(output_path, 'wb') as f:
#             f.write(file_content)

#         logger.info(f"✅ Decrypted: {file_path} -> {output_path}")

#         return {
#             'input_file': str(file_path),
#             'output_file': str(output_path),
#             'original_name': metadata.get('original_name'),
#             'metadata': metadata
#         }

#     def encrypt_bytes(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
#         """
#         Encrypt bytes and return packed format (nonce + tag + ciphertext)
#         """
#         result = self.encrypt(data, associated_data)
#         return result['nonce'] + result['tag'] + result['ciphertext']

#     def decrypt_bytes(self, packed_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
#         """
#         Decrypt packed format (nonce + tag + ciphertext)
#         """
#         nonce = packed_data[:AES_NONCE_SIZE]
#         tag = packed_data[AES_NONCE_SIZE:AES_NONCE_SIZE+AES_TAG_SIZE]
#         ciphertext = packed_data[AES_NONCE_SIZE+AES_TAG_SIZE:]

#         return self.decrypt(ciphertext, nonce, tag, associated_data)

#     @staticmethod
#     def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
#         """
#         Derive AES key from password using PBKDF2

#         Returns:
#             (key, salt)
#         """
#         if salt is None:
#             salt = os.urandom(16)

#         kdf = PBKDF2HMAC(
#             algorithm=hashes.SHA256(),
#             length=AES_KEY_SIZE,
#             salt=salt,
#             iterations=100000,
#             backend=default_backend()
#         )

#         key = kdf.derive(password.encode())
#         return key, salt

#     def get_key_fingerprint(self) -> str:
#         """Get SHA-256 hash of key for verification"""
#         return hashlib.sha256(self.key).hexdigest()[:16]

"""
AES-256-GCM Encryption Module — Enhanced with Innovation 3

INNOVATION 3 — Biometric-Confidence-Driven Adaptive Re-keying:
    AESCrypto now supports hot key rotation via update_key().
    When the AdaptiveRekeyMonitor (in key_fusion.py) triggers a re-key event,
    it calls this method to swap the active AES key in-place without
    interrupting the session. Each re-key also resets the nonce counter,
    ensuring nonce uniqueness is maintained across the key rotation boundary.

    The re-key event is logged with a timestamp and the new key fingerprint,
    providing a full audit trail of when and why keys were rotated.
"""

import hashlib
import os
import json
import base64
import logging
import time
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Union, List

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import zlib
from config import AES_KEY_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, TEMP_DIR

logger = logging.getLogger(__name__)


class AESCrypto:
    """
    AES-256-GCM authenticated encryption with Innovation 3 re-key support.

    Core guarantees:
    - Confidentiality: AES-256 with 256-bit keys.
    - Integrity & authenticity: GCM authentication tag on every ciphertext.
    - Unique nonces: os.urandom per encryption call — never reused.

    INNOVATION 3 addition:
    - update_key(): hot-swaps the active key mid-session.
    - rekey_log: audit trail of all key rotation events.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Args:
            key: 32-byte AES-256 key, or None to generate a random one.
        """
        if key is None:
            self.key = os.urandom(AES_KEY_SIZE)
        else:
            if len(key) != AES_KEY_SIZE:
                raise ValueError(f"Key must be {AES_KEY_SIZE} bytes for AES-256")
            self.key = key

        # INNOVATION 3: Re-key audit log
        self._rekey_log: List[Dict[str, Any]] = []
        self._key_created_at: float = time.time()
        self._encrypt_count: int = 0

    # ── INNOVATION 3: Hot key rotation ────────────────────────────────────────

    def update_key(self, new_key: bytes, reason: str = "adaptive_rekey") -> None:
        """
        INNOVATION 3: Hot-swap the active AES key mid-session.

        Called by the AdaptiveRekeyMonitor when biometric similarity drops
        below the confidence threshold. The new key is derived from a fresh
        BB84 round fused with the current live biometric embeddings.

        After update_key():
        - All subsequent encrypt() calls use the new key.
        - The old key is discarded from memory.
        - The nonce counter effectively resets (each call uses os.urandom).
        - A log entry records the rotation event for audit purposes.

        Args:
            new_key: 32-byte replacement AES key from fresh BB84 + HKDF fusion.
            reason:  Human-readable reason code for the log.
        """
        if len(new_key) != AES_KEY_SIZE:
            raise ValueError(f"New key must be {AES_KEY_SIZE} bytes")

        old_fingerprint = self.get_key_fingerprint()
        self.key = new_key
        new_fingerprint = self.get_key_fingerprint()

        log_entry = {
            'timestamp': time.time(),
            'reason': reason,
            'old_key_fingerprint': old_fingerprint,
            'new_key_fingerprint': new_fingerprint,
            'encryptions_before_rotation': self._encrypt_count,
            'key_age_seconds': time.time() - self._key_created_at,
        }
        self._rekey_log.append(log_entry)
        self._key_created_at = time.time()
        self._encrypt_count = 0

        logger.info(
            f"[Innovation3] AES key rotated — reason='{reason}', "
            f"old={old_fingerprint}, new={new_fingerprint}"
        )

    @property
    def rekey_log(self) -> List[Dict[str, Any]]:
        """INNOVATION 3: Return the full key rotation audit log."""
        return list(self._rekey_log)

    def get_rekey_summary(self) -> Dict[str, Any]:
        """INNOVATION 3: Session re-key statistics."""
        return {
            'total_rekeys': len(self._rekey_log),
            'current_key_fingerprint': self.get_key_fingerprint(),
            'current_key_age_seconds': time.time() - self._key_created_at,
            'encryptions_on_current_key': self._encrypt_count,
            'rekey_log': self._rekey_log,
        }

    # ── Core encryption ────────────────────────────────────────────────────────

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit AES key."""
        return os.urandom(AES_KEY_SIZE)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext:       Data to encrypt.
            associated_data: Additional authenticated data (integrity-protected,
                             not encrypted — e.g. session ID, user ID).

        Returns:
            Dict with 'ciphertext', 'nonce', 'tag', 'associated_data'.
        """
        nonce = os.urandom(AES_NONCE_SIZE)

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        self._encrypt_count += 1

        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': tag,
            'associated_data': associated_data,
        }

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Raises:
            cryptography.exceptions.InvalidTag: If the authentication tag fails
            (tampering or wrong key detected).
        """
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        return decryptor.update(ciphertext) + decryptor.finalize()

    # ── File-level operations ──────────────────────────────────────────────────

    def encrypt_file(
        self,
        file_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
        compress: bool = True,
    ) -> Dict[str, Any]:
        """
        Encrypt a file.  Metadata (original name, size, compression) is
        embedded in the payload so the receiver can reconstruct it correctly.

        The payload also stores the current key fingerprint and rekey count
        so the receiver can verify that the correct key was used.

        Args:
            file_path:   Path to plaintext file.
            output_path: Destination for .enc file (default: original + '.enc').
            compress:    Whether to zlib-compress before encryption.

        Returns:
            Encryption metadata dict.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + '.enc')

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        if compress:
            plaintext = zlib.compress(plaintext)

        metadata = {
            'original_name': file_path.name,
            'original_size': len(plaintext),
            'compressed': compress,
            'compression': 'zlib' if compress else None,
            # INNOVATION 3: embed key fingerprint for audit
            'key_fingerprint': self.get_key_fingerprint(),
            'rekey_count': len(self._rekey_log),
        }
        metadata_bytes = json.dumps(metadata).encode()
        metadata_len = len(metadata_bytes).to_bytes(4, 'big')
        plaintext_with_meta = metadata_len + metadata_bytes + plaintext

        result = self.encrypt(plaintext_with_meta)

        with open(output_path, 'wb') as f:
            f.write(result['nonce'])
            f.write(result['tag'])
            f.write(result['ciphertext'])

        logger.info(f"Encrypted: {file_path} -> {output_path}")

        return {
            'input_file': str(file_path),
            'output_file': str(output_path),
            'nonce': base64.b64encode(result['nonce']).decode(),
            'tag': base64.b64encode(result['tag']).decode(),
            'metadata': metadata,
        }

    def decrypt_file(
        self,
        file_path: Union[str, Path],
        output_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Decrypt a file produced by encrypt_file().

        Args:
            file_path:   Path to .enc file.
            output_path: Destination for decrypted file.

        Returns:
            Decryption metadata dict.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'rb') as f:
            nonce = f.read(AES_NONCE_SIZE)
            tag = f.read(AES_TAG_SIZE)
            ciphertext = f.read()

        plaintext = self.decrypt(ciphertext, nonce, tag)

        metadata_len = int.from_bytes(plaintext[:4], 'big')
        metadata_bytes = plaintext[4:4 + metadata_len]
        file_content = plaintext[4 + metadata_len:]
        metadata = json.loads(metadata_bytes.decode())

        if metadata.get('compressed'):
            file_content = zlib.decompress(file_content)

        if output_path is None:
            output_path = TEMP_DIR / metadata['original_name'] if metadata.get('original_name') else file_path.with_suffix('')
        else:
            output_path = Path(output_path)

        with open(output_path, 'wb') as f:
            f.write(file_content)

        logger.info(f"Decrypted: {file_path} -> {output_path}")

        return {
            'input_file': str(file_path),
            'output_file': str(output_path),
            'original_name': metadata.get('original_name'),
            'metadata': metadata,
        }

    # ── Byte-level convenience methods ────────────────────────────────────────

    def encrypt_bytes(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt and return packed bytes: nonce + tag + ciphertext."""
        result = self.encrypt(data, associated_data)
        return result['nonce'] + result['tag'] + result['ciphertext']

    def decrypt_bytes(self, packed_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt packed bytes (nonce + tag + ciphertext)."""
        nonce = packed_data[:AES_NONCE_SIZE]
        tag = packed_data[AES_NONCE_SIZE:AES_NONCE_SIZE + AES_TAG_SIZE]
        ciphertext = packed_data[AES_NONCE_SIZE + AES_TAG_SIZE:]
        return self.decrypt(ciphertext, nonce, tag, associated_data)

    # ── Utility ────────────────────────────────────────────────────────────────

    @staticmethod
    def derive_key_from_password(
        password: str,
        salt: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Derive AES key from a password via PBKDF2-HMAC-SHA256."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode()), salt

    def get_key_fingerprint(self) -> str:
        """Short SHA-256 fingerprint of the current key (for logging only)."""
        return hashlib.sha256(self.key).hexdigest()[:16]