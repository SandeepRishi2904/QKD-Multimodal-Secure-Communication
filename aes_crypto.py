"""
AES-256-GCM Encryption Module
Military-grade authenticated encryption
"""
import hashlib
import os
import json
import base64
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict, Any, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import zlib

from config import AES_KEY_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, TEMP_DIR

logger = logging.getLogger(__name__)

class AESCrypto:
    """
    AES-256-GCM authenticated encryption
    Provides confidentiality and integrity
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize with key or generate random key

        Args:
            key: 32-byte key for AES-256, or None to generate
        """
        if key is None:
            self.key = os.urandom(AES_KEY_SIZE)
        else:
            if len(key) != AES_KEY_SIZE:
                raise ValueError(f"Key must be {AES_KEY_SIZE} bytes for AES-256")
            self.key = key

    @staticmethod
    def generate_key() -> bytes:
        """Generate random 256-bit key"""
        return os.urandom(AES_KEY_SIZE)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Encrypt data using AES-256-GCM

        Args:
            plaintext: Data to encrypt
            associated_data: Additional authenticated data (not encrypted, but integrity protected)

        Returns:
            Dict with 'ciphertext', 'nonce', 'tag', and optional 'associated_data'
        """
        # Generate random nonce
        nonce = os.urandom(AES_NONCE_SIZE)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        # Add associated data if provided
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        return {
            'ciphertext': ciphertext,
            'nonce': nonce,
            'tag': tag,
            'associated_data': associated_data
        }

    def decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes, 
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt data using AES-256-GCM

        Args:
            ciphertext: Encrypted data
            nonce: Nonce used for encryption
            tag: Authentication tag
            associated_data: Additional authenticated data used during encryption

        Returns:
            Decrypted plaintext

        Raises:
            Exception: If authentication fails (tampering detected)
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # Add associated data if provided
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def encrypt_file(self, file_path: Union[str, Path], 
                   output_path: Optional[Union[str, Path]] = None,
                   compress: bool = True) -> Dict[str, Any]:
        """
        Encrypt a file

        Args:
            file_path: Path to file to encrypt
            output_path: Output path (default: original + '.enc')
            compress: Whether to compress before encryption

        Returns:
            Encryption metadata
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if output_path is None:
            output_path = file_path.with_suffix(file_path.suffix + '.enc')
        else:
            output_path = Path(output_path)

        # Read file
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        # Compress if requested
        if compress:
            plaintext = zlib.compress(plaintext)
            is_compressed = True
        else:
            is_compressed = False

        # Add metadata header
        metadata = {
            'original_name': file_path.name,
            'original_size': len(plaintext),
            'compressed': is_compressed,
            'compression': 'zlib' if is_compressed else None
        }
        metadata_bytes = json.dumps(metadata).encode()

        # Combine metadata length + metadata + plaintext
        metadata_len = len(metadata_bytes).to_bytes(4, 'big')
        plaintext_with_meta = metadata_len + metadata_bytes + plaintext

        # Encrypt
        encryption_result = self.encrypt(plaintext_with_meta)

        # Write to file
        with open(output_path, 'wb') as f:
            f.write(encryption_result['nonce'])
            f.write(encryption_result['tag'])
            f.write(encryption_result['ciphertext'])

        logger.info(f"✅ Encrypted: {file_path} -> {output_path}")

        return {
            'input_file': str(file_path),
            'output_file': str(output_path),
            'nonce': base64.b64encode(encryption_result['nonce']).decode(),
            'tag': base64.b64encode(encryption_result['tag']).decode(),
            'metadata': metadata
        }

    def decrypt_file(self, file_path: Union[str, Path], 
                    output_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
        """
        Decrypt a file

        Args:
            file_path: Path to encrypted file
            output_path: Output path (default: from metadata or strip .enc)

        Returns:
            Decryption metadata
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Read encrypted file
        with open(file_path, 'rb') as f:
            nonce = f.read(AES_NONCE_SIZE)
            tag = f.read(AES_TAG_SIZE)
            ciphertext = f.read()

        # Decrypt
        plaintext = self.decrypt(ciphertext, nonce, tag)

        # Parse metadata
        metadata_len = int.from_bytes(plaintext[:4], 'big')
        metadata_bytes = plaintext[4:4+metadata_len]
        file_content = plaintext[4+metadata_len:]

        metadata = json.loads(metadata_bytes.decode())

        # Decompress if needed
        if metadata.get('compressed'):
            file_content = zlib.decompress(file_content)

        # Determine output path
        if output_path is None:
            if metadata.get('original_name'):
                output_path = TEMP_DIR / metadata['original_name']
            else:
                output_path = file_path.with_suffix('')
        else:
            output_path = Path(output_path)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(file_content)

        logger.info(f"✅ Decrypted: {file_path} -> {output_path}")

        return {
            'input_file': str(file_path),
            'output_file': str(output_path),
            'original_name': metadata.get('original_name'),
            'metadata': metadata
        }

    def encrypt_bytes(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt bytes and return packed format (nonce + tag + ciphertext)
        """
        result = self.encrypt(data, associated_data)
        return result['nonce'] + result['tag'] + result['ciphertext']

    def decrypt_bytes(self, packed_data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt packed format (nonce + tag + ciphertext)
        """
        nonce = packed_data[:AES_NONCE_SIZE]
        tag = packed_data[AES_NONCE_SIZE:AES_NONCE_SIZE+AES_TAG_SIZE]
        ciphertext = packed_data[AES_NONCE_SIZE+AES_TAG_SIZE:]

        return self.decrypt(ciphertext, nonce, tag, associated_data)

    @staticmethod
    def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Derive AES key from password using PBKDF2

        Returns:
            (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = kdf.derive(password.encode())
        return key, salt

    def get_key_fingerprint(self) -> str:
        """Get SHA-256 hash of key for verification"""
        return hashlib.sha256(self.key).hexdigest()[:16]
