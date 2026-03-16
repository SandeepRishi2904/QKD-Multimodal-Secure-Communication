"""
Input Validation and Security Utilities
"""
import re
import magic
from pathlib import Path
from typing import Tuple, Optional
import hashlib
import logging

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Validates all inputs for security concerns"""

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.json'}

    # Dangerous patterns in filenames
    DANGEROUS_PATTERNS = [
        r'\.\.',  # Directory traversal
        r'[~#%&*{}\\:<>?/|"]', 
        r'^(con|prn|aux|nul|com[0-9]|lpt[0-9])$',  # Windows reserved names
    ]

    @staticmethod
    def validate_filename(filename: str) -> Tuple[bool, str]:
        """
        Validate filename for security
        Returns: (is_valid, error_message)
        """
        if not filename or len(filename) > 255:
            return False, "Invalid filename length"

        # Check for directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, "Directory traversal attempt detected"

        # Check dangerous patterns
        for pattern in SecurityValidator.DANGEROUS_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                return False, f"Dangerous pattern detected in filename"

        # Check extension
        ext = Path(filename).suffix.lower()
        if ext not in SecurityValidator.ALLOWED_EXTENSIONS:
            return False, f"File extension '{ext}' not allowed"

        return True, "Valid"

    @staticmethod
    def validate_file_content(file_path: Path, expected_mime: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate file content using magic numbers
        """
        try:
            mime = magic.from_file(str(file_path), mime=True)

            # Check for executable content
            dangerous_mimes = [
                'application/x-executable',
                'application/x-dosexec',
                'application/x-shellscript',
                'text/x-python',
                'text/x-script'
            ]

            if any(d in mime for d in dangerous_mimes):
                return False, f"Dangerous file type detected: {mime}"

            if expected_mime and not mime.startswith(expected_mime):
                return False, f"MIME type mismatch: expected {expected_mime}, got {mime}"

            return True, mime

        except Exception as e:
            logger.error(f"File validation error: {e}")
            return False, str(e)

    @staticmethod
    def calculate_file_hash(file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not input_str:
            return ""

        # Remove control characters
        sanitized = re.sub(r'[\x00-\x1F\x7F]', '', input_str)

        # Limit length
        sanitized = sanitized[:max_length]

        # Strip whitespace
        return sanitized.strip()

class BiometricValidator:
    """Validates biometric data quality"""

    @staticmethod
    def validate_face_image(image_path: Path) -> Tuple[bool, str]:
        """Validate face image quality"""
        try:
            from PIL import Image

            img = Image.open(image_path)

            # Check minimum dimensions
            if img.width < 100 or img.height < 100:
                return False, "Face image too small (min 100x100)"

            # Check aspect ratio
            aspect = img.width / img.height
            if aspect < 0.5 or aspect > 2.0:
                return False, "Invalid aspect ratio"

            # Check color mode
            if img.mode not in ['RGB', 'RGBA', 'L']:
                return False, "Invalid color mode"

            return True, "Valid face image"

        except Exception as e:
            return False, f"Invalid image: {str(e)}"

    @staticmethod
    def validate_fingerprint_template(template_data: bytes) -> Tuple[bool, str]:
        """Validate fingerprint template data"""
        if not template_data or len(template_data) < 100:
            return False, "Fingerprint template too small"

        if len(template_data) > 10000:
            return False, "Fingerprint template too large"

        return True, "Valid fingerprint template"
