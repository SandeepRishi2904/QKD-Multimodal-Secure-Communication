#!/usr/bin/env python3
"""
Face Enrollment Script - Sender
One-time setup to enroll sender's face template
"""
import sys
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from face_auth import FaceAuthenticator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    print("=" * 60)
    print("🔐 QKD MULTIMODAL SYSTEM - Face Enrollment (Sender)")
    print("=" * 60)
    print()

    auth = FaceAuthenticator()

    print("📷 This will capture your face for authentication.")
    print("Instructions:")
    print("  1. Ensure good lighting on your face")
    print("  2. Look directly at the camera")
    print("  3. Press SPACE when face is detected to capture")
    print("  4. Press ESC to cancel")
    print()

    input("Press ENTER to start enrollment...")

    success, message = auth.enroll_face(identity='sender')

    print()
    if success:
        print("✅ " + message)
        print("\nYour face template has been saved securely.")
        print("You can now use face authentication as sender.")
    else:
        print("❌ Enrollment failed: " + message)
        sys.exit(1)

if __name__ == "__main__":
    main()
