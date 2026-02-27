"""
QKD Multimodal Secure Communication System - Streamlit Frontend
Interactive UI for sender and receiver operations
"""
import os
import sys
import json
import base64
import argparse
import requests
from pathlib import Path
from datetime import datetime
import tempfile

import streamlit as st
from PIL import Image
import numpy as np

# Page config
st.set_page_config(
    page_title="QKD Multimodal Secure Communication",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('--mode', type=str, default='sender', choices=['sender', 'receiver'])
parser.add_argument('--port', type=int, default=8501)
parser.add_argument('--backend', type=str, default='http://localhost:8000')
args, _ = parser.parse_known_args()

# Configuration
MODE = args.mode
BACKEND_URL = args.backend
API_BASE = f"{BACKEND_URL}"

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .auth-box {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 1rem;
        color: white;
        text-align: center;
        margin: 2rem 0;
    }
    .stButton>button {
        width: 100%;
        border-radius: 0.5rem;
        height: 3rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'session_id' not in st.session_state:
    st.session_state.session_id = None
if 'sender_session_id' not in st.session_state:
    st.session_state.sender_session_id = None  # Store sender session separately
if 'receiver_session_id' not in st.session_state:
    st.session_state.receiver_session_id = None  # Store receiver session separately
if 'sender_authenticated' not in st.session_state:
    st.session_state.sender_authenticated = False
if 'receiver_authenticated' not in st.session_state:
    st.session_state.receiver_authenticated = False
if 'identity' not in st.session_state:
    st.session_state.identity = MODE
if 'key_fingerprint' not in st.session_state:
    st.session_state.key_fingerprint = None

def check_backend():
    """Check if backend is running"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def authenticate(identity, auth_mode):
    """Call backend authentication"""
    try:
        response = requests.post(
            f"{API_BASE}/authenticate",
            json={"identity": identity, "mode": auth_mode},
            timeout=60
        )
        return response.json()
    except Exception as e:
        return {"success": False, "message": str(e)}

def switch_identity_backend(new_identity, current_identity):
    """Check if we can switch identity"""
    # Determine which session to use
    current_session = None
    if current_identity == "sender" and st.session_state.sender_session_id:
        current_session = st.session_state.sender_session_id
    elif current_identity == "receiver" and st.session_state.receiver_session_id:
        current_session = st.session_state.receiver_session_id
    
    try:
        response = requests.post(
            f"{API_BASE}/switch_identity",
            json={
                "session_id": current_session,
                "new_identity": new_identity,
                "current_identity": current_identity
            },
            timeout=30
        )
        return response.json()
    except Exception as e:
        return {"success": False, "message": str(e), "requires_authentication": True}

def upload_and_encrypt(file, session_id, compress=True):
    """Upload and encrypt file"""
    try:
        files = {"file": (file.name, file.getvalue(), file.type)}
        data = {"session_id": session_id, "compress": compress}

        response = requests.post(
            f"{API_BASE}/encrypt",
            files=files,
            data=data,
            timeout=120
        )

        if response.status_code == 200:
            return True, response.content, response.headers.get('X-Encryption-Metadata', '{}')
        else:
            return False, response.json().get('detail', 'Unknown error'), None
    except Exception as e:
        return False, str(e), None

def upload_and_decrypt(file, session_id):
    """Upload and decrypt file"""
    try:
        files = {"file": (file.name, file.getvalue(), file.type)}
        data = {"session_id": session_id}

        response = requests.post(
            f"{API_BASE}/decrypt",
            files=files,
            data=data,
            timeout=120
        )

        if response.status_code == 200:
            return True, response.content, response.headers.get('X-Decryption-Metadata', '{}')
        else:
            return False, response.json().get('detail', 'Unknown error'), None
    except Exception as e:
        return False, str(e), None

def main():
    # Header
    st.markdown(f'<div class="main-header">🔐 QKD Multimodal Secure Communication</div>', unsafe_allow_html=True)
    
    # Show current status
    status_text = f"Mode: <b>{st.session_state.identity.upper()}</b>"
    if st.session_state.identity == "sender" and st.session_state.sender_authenticated:
        status_text += " | ✅ Sender Authenticated"
    elif st.session_state.identity == "receiver" and st.session_state.receiver_authenticated:
        status_text += " | ✅ Receiver Authenticated"
    elif st.session_state.identity == "sender" and not st.session_state.sender_authenticated:
        status_text += " | ⏳ Not Authenticated"
    elif st.session_state.identity == "receiver" and not st.session_state.receiver_authenticated:
        status_text += " | ⏳ Not Authenticated"
    
    st.markdown(f'<div class="sub-header">{status_text}</div>', unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")

        # Backend status
        if check_backend():
            st.success("🟢 Backend Connected")
        else:
            st.error("🔴 Backend Disconnected")

        st.divider()

        # Authentication status display
        st.subheader("🔐 Auth Status")
        if st.session_state.sender_authenticated:
            st.success("✅ Sender: Authenticated")
        else:
            st.error("❌ Sender: Not Authenticated")
            
        if st.session_state.receiver_authenticated:
            st.success("✅ Receiver: Authenticated")
        else:
            st.error("❌ Receiver: Not Authenticated")

        st.divider()

        # Identity selection
        st.subheader("Switch Identity")
        
        selected_identity = st.radio(
            "Select identity:",
            ["sender", "receiver"],
            index=0 if st.session_state.identity == "sender" else 1,
        )
        
        # Handle identity switch
        if selected_identity != st.session_state.identity:
            # Check if target identity needs authentication
            if selected_identity == "receiver":
                if not st.session_state.receiver_authenticated:
                    st.session_state.identity = "receiver"
                    st.warning("⚠️ Switching to Receiver - Authentication Required!")
                    st.rerun()
                else:
                    st.session_state.identity = "receiver"
                    st.success("Switched to Receiver (already authenticated)")
                    st.rerun()
            else:  # switching to sender
                if not st.session_state.sender_authenticated:
                    st.session_state.identity = "sender"
                    st.warning("⚠️ Switching to Sender - Authentication Required!")
                    st.rerun()
                else:
                    st.session_state.identity = "sender"
                    st.success("Switched to Sender (already authenticated)")
                    st.rerun()

        # Logout button
        if st.button("🚪 Logout All", type="secondary"):
            st.session_state.sender_authenticated = False
            st.session_state.receiver_authenticated = False
            st.session_state.sender_session_id = None
            st.session_state.receiver_session_id = None
            st.session_state.session_id = None
            st.session_state.key_fingerprint = None
            st.rerun()

    # Main content area - Determine what to show
    current_identity = st.session_state.identity
    
    # Check if current identity needs authentication
    needs_auth = False
    if current_identity == "sender" and not st.session_state.sender_authenticated:
        needs_auth = True
    elif current_identity == "receiver" and not st.session_state.receiver_authenticated:
        needs_auth = True

    if needs_auth:
        # Show authentication screen
        st.markdown(f'''
        <div class="auth-box">
            <h2>🔐 {current_identity.upper()} Authentication Required</h2>
            <p>Please authenticate with your face and fingerprint to continue</p>
        </div>
        ''', unsafe_allow_html=True)

        col1, col2 = st.columns([2, 1])

        with col1:
            st.info(f"""
            **Authentication for {current_identity.upper()}:**
            
            1. **Face Recognition** - Look at camera
            2. **Fingerprint Scan** - Place finger on sensor
            
            **Requirements:**
            - Enrolled face template for **{current_identity}**
            - Enrolled fingerprint template for **{current_identity}**
            """)

            auth_mode = st.selectbox(
                "Authentication Mode:",
                ["full", "face", "fingerprint"],
                index=0,
                key="auth_mode"
            )

            if st.button("🔓 Authenticate Now", type="primary", use_container_width=True):
                with st.spinner(f"Authenticating as {current_identity}... Look at camera"):
                    result = authenticate(current_identity, auth_mode)

                if result.get('success'):
                    session_id = result.get('session_id')
                    
                    # Store session based on identity
                    if current_identity == "sender":
                        st.session_state.sender_session_id = session_id
                        st.session_state.sender_authenticated = True
                    else:
                        st.session_state.receiver_session_id = session_id
                        st.session_state.receiver_authenticated = True
                    
                    st.session_state.session_id = session_id
                    st.session_state.key_fingerprint = result.get('key_fingerprint')

                    st.success(f"✅ {current_identity.upper()} Authentication Successful!")
                    
                    # Show confidence metrics
                    cols = st.columns(2)
                    with cols[0]:
                        st.metric("Face Confidence", f"{result.get('face_confidence', 0):.2%}")
                    with cols[1]:
                        st.metric("Fingerprint Confidence", f"{result.get('fingerprint_confidence', 0):.2%}")

                    st.rerun()
                else:
                    st.error(f"❌ Authentication Failed: {result.get('message', 'Unknown error')}")

        with col2:
            st.subheader("Enrollment Status")
            try:
                response = requests.get(f"{API_BASE}/enrollment/{current_identity}", timeout=5)
                if response.status_code == 200:
                    status = response.json()

                    if status['face_enrolled']:
                        st.success("✅ Face Enrolled")
                    else:
                        st.error("❌ Face Not Enrolled")
                        st.caption(f"Run: `python scripts/enroll_face_{current_identity}.py`")

                    if status['fingerprint_enrolled']:
                        st.success("✅ Fingerprint Enrolled")
                    else:
                        st.error("❌ Fingerprint Not Enrolled")
                        st.caption(f"Run: `python scripts/enroll_fingerprint_{current_identity}.py`")
            except Exception as e:
                st.error(f"Cannot check enrollment: {e}")

    else:
        # Authenticated - show operations
        st.header(f"📁 {current_identity.upper()} Operations")

        if current_identity == "sender":
            # Sender: Encrypt and Send
            st.subheader("🔒 Encrypt & Send File")

            uploaded_file = st.file_uploader(
                "Choose file to encrypt",
                type=['txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'zip', 'json'],
                help="Max file size: 100MB"
            )

            compress = st.checkbox("Compress before encryption", value=True)

            if uploaded_file is not None:
                col1, col2 = st.columns([1, 1])

                with col1:
                    st.info(f"**File:** {uploaded_file.name}")
                    st.info(f"**Size:** {len(uploaded_file.getvalue()) / 1024:.2f} KB")
                    st.info(f"**Type:** {uploaded_file.type}")

                with col2:
                    if st.button("🔐 Encrypt & Download", type="primary", use_container_width=True):
                        with st.spinner("Encrypting..."):
                            success, data, metadata = upload_and_encrypt(
                                uploaded_file, 
                                st.session_state.sender_session_id,
                                compress
                            )

                        if success:
                            st.success("✅ File encrypted successfully!")
                            
                            if metadata:
                                meta = json.loads(metadata)
                                st.json(meta)

                            output_filename = f"{uploaded_file.name}.enc"
                            st.download_button(
                                label="⬇️ Download Encrypted File",
                                data=data,
                                file_name=output_filename,
                                mime="application/octet-stream"
                            )

                            st.info("📤 Encrypted! Now switch to Receiver mode to decrypt.")
                            
                            # Quick switch button
                            if st.button("🔄 Switch to Receiver Mode", type="secondary"):
                                if not st.session_state.receiver_authenticated:
                                    st.session_state.identity = "receiver"
                                    st.warning("⚠️ Receiver authentication required!")
                                    st.rerun()
                                else:
                                    st.session_state.identity = "receiver"
                                    st.success("Switched to Receiver!")
                                    st.rerun()
                        else:
                            st.error(f"❌ Encryption failed: {data}")

        else:
            # Receiver: Decrypt
            st.subheader("🔓 Decrypt Received File")

            encrypted_file = st.file_uploader(
                "Choose encrypted file",
                type=['enc'],
                help="Upload .enc file from sender"
            )

            if encrypted_file is not None:
                col1, col2 = st.columns([1, 1])

                with col1:
                    st.info(f"**File:** {encrypted_file.name}")
                    st.info(f"**Size:** {len(encrypted_file.getvalue()) / 1024:.2f} KB")

                with col2:
                    if st.button("🔓 Decrypt & Download", type="primary", use_container_width=True):
                        with st.spinner("Decrypting..."):
                            success, data, metadata = upload_and_decrypt(
                                encrypted_file,
                                st.session_state.receiver_session_id
                            )

                        if success:
                            st.success("✅ File decrypted successfully!")

                            if metadata:
                                meta = json.loads(metadata)
                                original_name = meta.get('original_name', 'decrypted_file')
                                st.json(meta)
                            else:
                                original_name = encrypted_file.name.replace('.enc', '')

                            st.download_button(
                                label="⬇️ Download Decrypted File",
                                data=data,
                                file_name=original_name,
                                mime="application/octet-stream"
                            )
                            
                            st.info("✅ Decryption complete!")
                        else:
                            st.error(f"❌ Decryption failed: {data}")

        # Security info
        with st.expander("🔍 Security Details"):
            st.json({
                "current_identity": current_identity,
                "sender_authenticated": st.session_state.sender_authenticated,
                "receiver_authenticated": st.session_state.receiver_authenticated,
                "sender_session": st.session_state.sender_session_id[:8] if st.session_state.sender_session_id else None,
                "receiver_session": st.session_state.receiver_session_id[:8] if st.session_state.receiver_session_id else None,
                "key_fingerprint": st.session_state.key_fingerprint,
                "timestamp": datetime.now().isoformat()
            })

if __name__ == "__main__":
    main()