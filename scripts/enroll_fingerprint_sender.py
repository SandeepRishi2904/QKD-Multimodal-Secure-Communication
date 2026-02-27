#!/usr/bin/env python3
"""
Fingerprint Enrollment Script - Sender
One-time setup to enroll sender's fingerprint template
"""
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fingerprint_auth import FingerprintAuthenticator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    print("=" * 60)
    print("🔐 QKD MULTIMODAL SYSTEM - Fingerprint Enrollment (Sender)")
    print("=" * 60)
    print()

    # Try hardware first, fallback to simulation
    auth = FingerprintAuthenticator(use_simulation=False)

    print("🖐️  This will capture your fingerprint for authentication.")
    print("Instructions:")
    print("  1. Clean your finger")
    print("  2. Place finger firmly on sensor")
    print("  3. Follow prompts for multiple samples")
    print()

    input("Press ENTER to start enrollment...")

    success, message = auth.enroll_fingerprint(identity='sender')

    print()
    if success:
        print("✅ " + message)
        print("\nYour fingerprint template has been saved securely.")
        print("You can now use fingerprint authentication as sender.")
    else:
        print("❌ Enrollment failed: " + message)
        sys.exit(1)

    auth.close()

if __name__ == "__main__":
    main()
