"""
QKD Multimodal Secure Communication System - Streamlit Frontend
Interactive UI for sender and receiver operations WITH ENROLLMENT
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
import streamlit.components.v1 as components

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
    .enroll-box {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
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
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #28a745;
    }
    .warning-box {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #ffc107;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #dc3545;
    }
    .enroll-nav-box {
        background-color: #e7f3ff;
        border: 2px solid #1f77b4;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'session_id' not in st.session_state:
    st.session_state.session_id = None
if 'sender_session_id' not in st.session_state:
    st.session_state.sender_session_id = None
if 'receiver_session_id' not in st.session_state:
    st.session_state.receiver_session_id = None
if 'sender_authenticated' not in st.session_state:
    st.session_state.sender_authenticated = False
if 'receiver_authenticated' not in st.session_state:
    st.session_state.receiver_authenticated = False
if 'identity' not in st.session_state:
    st.session_state.identity = MODE
if 'key_fingerprint' not in st.session_state:
    st.session_state.key_fingerprint = None
# Enrollment state
if 'enrollment_step' not in st.session_state:
    st.session_state.enrollment_step = 1
if 'enrollment_identity' not in st.session_state:
    st.session_state.enrollment_identity = None
if 'face_captured' not in st.session_state:
    st.session_state.face_captured = False
if 'fingerprint_captured' not in st.session_state:
    st.session_state.fingerprint_captured = False
if 'current_page' not in st.session_state:
    st.session_state.current_page = "main"

def check_backend():
    """Check if backend is running"""
    try:
        response = requests.get(f"{API_BASE}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_enrollment_status(identity):
    """Get enrollment status from backend"""
    try:
        response = requests.get(f"{API_BASE}/enrollment/{identity}", timeout=5)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        st.error(f"Cannot check enrollment: {e}")
        return None

def authenticate(identity, auth_mode, simulate_eavesdrop=False):
    """Call backend authentication"""
    try:
        response = requests.post(
            f"{API_BASE}/authenticate",
            json={
                "identity": identity, 
                "mode": auth_mode.lower(),
                "simulate_eavesdrop": simulate_eavesdrop
            },
            timeout=60
        )
        return response.json()
    except Exception as e:
        return {"success": False, "message": str(e)}

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

def reset_enrollment_state():
    """Reset enrollment state"""
    st.session_state.enrollment_step = 1
    st.session_state.enrollment_identity = None
    st.session_state.face_captured = False
    st.session_state.fingerprint_captured = False

def return_to_main_app():
    """Redirect to the respective main app port"""
    port = 8501 if st.session_state.identity == "sender" else 8502
    st.markdown(f'<meta http-equiv="refresh" content="0;url=http://localhost:{port}">', unsafe_allow_html=True)
    st.info(f"Redirecting to Main App on port {port}...")

def go_to_enrollment():
    """Redirect to enrollment page"""
    st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8503">', unsafe_allow_html=True)
    st.info("Redirecting to Enrollment page...")
    st.markdown("[Click here if not redirected](http://localhost:8503)")

def show_enrollment_section():
    """Show enrollment UI section"""
    st.markdown('<div class="enroll-box"><h2>📝 Biometric Enrollment</h2><p>First-time setup for secure communication</p></div>', unsafe_allow_html=True)
    
    # Navigation button to go back to main
    st.subheader("🧭 Navigation")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🏠 Go to Main App", use_container_width=True, key="enroll_nav_main"):
            reset_enrollment_state()
            return_to_main_app()
    with col2:
        if st.button("🔄 Refresh Page", use_container_width=True, key="enroll_nav_refresh"):
            st.rerun()
    
    st.divider()
    
    # Check current enrollment status
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("👤 Sender Status")
        sender_status = get_enrollment_status("sender")
        if sender_status:
            if sender_status['face_enrolled']:
                st.success("✅ Face Enrolled")
            else:
                st.error("❌ Face Not Enrolled")
            
            if sender_status['fingerprint_enrolled']:
                st.success("✅ Fingerprint Enrolled")
            else:
                st.error("❌ Fingerprint Not Enrolled")
            
            if sender_status['fully_enrolled']:
                st.success("🎉 Sender Fully Enrolled!")
        else:
            st.warning("⚠️ Cannot check status")
    
    with col2:
        st.subheader("👤 Receiver Status")
        receiver_status = get_enrollment_status("receiver")
        if receiver_status:
            if receiver_status['face_enrolled']:
                st.success("✅ Face Enrolled")
            else:
                st.error("❌ Face Not Enrolled")
            
            if receiver_status['fingerprint_enrolled']:
                st.success("✅ Fingerprint Enrolled")
            else:
                st.error("❌ Fingerprint Not Enrolled")
            
            if receiver_status['fully_enrolled']:
                st.success("🎉 Receiver Fully Enrolled!")
        else:
            st.warning("⚠️ Cannot check status")
    
    st.divider()
    
    # Enrollment wizard
    st.subheader("🚀 Enrollment Wizard")
    
    # Step 1: Select Identity
    if st.session_state.enrollment_step == 1:
        st.info("**Step 1 of 3**: Select who you want to enroll")
        
        identity = st.radio(
            "Select Identity to Enroll:",
            ["Sender", "Receiver"],
            horizontal=True,
            key="enroll_identity_select"
        )
        
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("Next →", type="primary", use_container_width=True, key="enroll_step1_next"):
                st.session_state.enrollment_identity = identity
                st.session_state.enrollment_step = 2
                st.rerun()
    
    # Step 2: Face Enrollment
    elif st.session_state.enrollment_step == 2:
        identity = st.session_state.enrollment_identity
        st.info(f"**Step 2 of 3**: Enroll Face for **{identity.upper()}**")
        
        st.warning("📸 Please ensure:\n- Good lighting on your face\n- Remove glasses/mask if possible\n- Look directly at camera")
        
        # Camera capture for face
        camera_image = st.camera_input("Capture your face", key="face_camera")
        
        if camera_image is not None:
            st.image(camera_image, caption="Captured Face", use_column_width=True)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("↻ Retake", use_container_width=True, key="enroll_face_retake"):
                    st.rerun()
            with col2:
                if st.button("✓ Save Face", type="primary", use_container_width=True, key="enroll_face_save"):
                    with st.spinner("Processing face enrollment..."):
                        # Convert to bytes and send to backend
                        files = {"image": ("face.jpg", camera_image.getvalue(), "image/jpeg")}
                        data = {"identity": identity}
                        
                        try:
                            response = requests.post(
                                f"{API_BASE}/enroll/face",
                                files=files,
                                data=data,
                                timeout=30
                            )
                            result = response.json()
                            
                            if result.get('success'):
                                st.session_state.face_captured = True
                                st.success(f"✅ {result.get('message', 'Face enrolled successfully')}")
                                
                                # Check if we need fingerprint too
                                status = get_enrollment_status(identity)
                                if status and status.get('fingerprint_enrolled'):
                                    st.session_state.enrollment_step = 4  # Skip to complete
                                else:
                                    st.session_state.enrollment_step = 3  # Go to fingerprint
                                st.rerun()
                            else:
                                st.error(f"❌ {result.get('message', 'Face enrollment failed')}")
                        except Exception as e:
                            st.error(f"❌ Error: {e}")
        
        # Alternative: Upload photo
        with st.expander("Or upload a photo instead"):
            uploaded_photo = st.file_uploader("Choose a photo", type=['jpg', 'jpeg', 'png'], key="enroll_face_upload")
            if uploaded_photo is not None:
                st.image(uploaded_photo, caption="Uploaded Photo")
                if st.button("Use This Photo", type="primary", key="enroll_face_upload_btn"):
                    with st.spinner("Processing..."):
                        files = {"image": (uploaded_photo.name, uploaded_photo.getvalue(), uploaded_photo.type)}
                        data = {"identity": identity}
                        
                        try:
                            response = requests.post(
                                f"{API_BASE}/enroll/face",
                                files=files,
                                data=data,
                                timeout=30
                            )
                            result = response.json()
                            
                            if result.get('success'):
                                st.session_state.face_captured = True
                                st.success(f"✅ {result.get('message')}")
                                st.session_state.enrollment_step = 3
                                st.rerun()
                            else:
                                st.error(f"❌ {result.get('message')}")
                        except Exception as e:
                            st.error(f"❌ Error: {e}")
    
    # Step 3: Fingerprint Enrollment
    elif st.session_state.enrollment_step == 3:
        identity = st.session_state.enrollment_identity
        st.info(f"**Step 3 of 3**: Enroll Fingerprint for **{identity.upper()}**")
        
        st.warning("🖐️ Instructions:\n1. Place your finger on the sensor\n2. Hold for 2-3 seconds\n3. Lift and place again (3 samples needed for hardware)")
        
        # Check if hardware or simulation
        try:
            response = requests.get(f"{API_BASE}/fingerprint/info", timeout=5)
            fp_info = response.json() if response.status_code == 200 else {"mode": "unknown"}
        except:
            fp_info = {"mode": "unknown"}
        
        if fp_info.get('mode') == 'simulation':
            st.info("ℹ️ Running in **Simulation Mode** (no hardware detected). A simulated fingerprint will be generated for testing.")
        else:
            st.success("✅ Hardware fingerprint sensor detected!")
        
        if st.button("🖐️ Start Fingerprint Enrollment", type="primary", use_container_width=True, key="enroll_fp_start"):
            with st.spinner("Capturing fingerprint... Please place your finger on the sensor"):
                try:
                    response = requests.post(
                        f"{API_BASE}/enroll/fingerprint",
                        json={"identity": identity},
                        timeout=60
                    )
                    result = response.json()
                    
                    if result.get('success'):
                        st.session_state.fingerprint_captured = True
                        st.success(f"✅ {result.get('message', 'Fingerprint enrolled successfully')}")
                        st.session_state.enrollment_step = 4
                        st.rerun()
                    else:
                        st.error(f"❌ {result.get('message', 'Fingerprint enrollment failed')}")
                except Exception as e:
                    st.error(f"❌ Error: {e}")
    
    # Step 4: Complete
    elif st.session_state.enrollment_step == 4:
        identity = st.session_state.enrollment_identity
        st.markdown(f'<div class="success-box"><h3>🎉 Enrollment Complete!</h3><p><b>{identity.upper()}</b> is now fully enrolled and ready for secure communication.</p></div>', unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 1, 1])
        with col1:
            if st.button("🏠 Go to Main App", use_container_width=True, key="enroll_complete_main"):
                reset_enrollment_state()
                return_to_main_app()
        with col2:
            if st.button("➕ Enroll Another", type="primary", use_container_width=True, key="enroll_complete_another"):
                reset_enrollment_state()
                st.rerun()
        with col3:
            if st.button("🔓 Start Authentication", use_container_width=True, key="enroll_complete_auth"):
                reset_enrollment_state()
                return_to_main_app()

def show_continuous_auth_widget():
    """Show continuous face authentication HTML component"""
    

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: sans-serif; margin: 0; padding: 10px; background-color: #f0f2f6; border-radius: 8px; }}
            #video-container {{ display: flex; flex-direction: column; align-items: center; justify-content: center; }}
            video {{ border-radius: 8px; max-width: 100%; height: auto; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 10px; }}
            #status-badge {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 14px; text-align: center; }}
            .status-checking {{ background-color: #f39c12; }}
            .status-success {{ background-color: #2ecc71; }}
            .status-fail {{ background-color: #e74c3c; }}
            #logs {{ margin-top: 10px; font-size: 12px; color: #666; max-height: 100px; overflow-y: auto; width: 100%; }}
        </style>
    </head>
    <body>
        <div id="video-container">
            <video id="video" width="240" height="180" autoplay playsinline></video>
            <div id="status-badge" class="status-checking">Initializing Camera...</div>
            <div id="logs"></div>
            <canvas id="canvas" width="240" height="180" style="display:none;"></canvas>
        </div>
        <script>
            const video = document.getElementById('video');
            const canvas = document.getElementById('canvas');
            const statusBadge = document.getElementById('status-badge');
            const logs = document.getElementById('logs');
            const backendUrl = "{API_BASE}";
            const identity = "{st.session_state.identity}";
            
            function log(msg) {{
                const d = new Date();
                const timeStr = d.toLocaleTimeString();
                logs.innerHTML = `<div>[${{timeStr}}] ${{msg}}</div>` + logs.innerHTML;
            }}

            async function startCamera() {{
                try {{
                    const stream = await navigator.mediaDevices.getUserMedia({{ video: true }});
                    video.srcObject = stream;
                    statusBadge.textContent = "Authenticating...";
                    statusBadge.className = "status-checking";
                    log("Camera started - will capture every 5 seconds");
                    
                    // Initial capture
                    setTimeout(captureAndAuthenticate, 2000);
                    // Start capture interval
                    setInterval(captureAndAuthenticate, 5000);
                }} catch (err) {{
                    statusBadge.textContent = "Camera Error";
                    statusBadge.className = "status-fail";
                    log("Error accessing camera: " + err.message);
                }}
            }}

            async function captureAndAuthenticate() {{
                if (!video.srcObject) return;
                
                const context = canvas.getContext('2d');
                context.drawImage(video, 0, 0, canvas.width, canvas.height);
                const imageData = canvas.toDataURL('image/jpeg', 0.8);
                
                try {{
                    const response = await fetch(`${{backendUrl}}/authenticate/continuous`, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ identity: identity, image: imageData }})
                    }});
                    
                    const result = await response.json();
                    if (result.success) {{
                        statusBadge.textContent = "✅ Authenticated";
                        statusBadge.className = "status-success";
                        log(`Success (Conf: ${{result.confidence ? result.confidence.toFixed(2) : 'N/A'}}). Wait 5s...`);
                    }} else {{
                        statusBadge.textContent = "❌ Auth Failed";
                        statusBadge.className = "status-fail";
                        log(`Failed: ${{result.message}}`);
                    }}
                }} catch (err) {{
                    statusBadge.textContent = "Backend Error";
                    statusBadge.className = "status-fail";
                    log("Network error contacting backend");
                }}
            }}

            // Start everything
            startCamera();
        </script>
    </body>
    </html>
    """
    
    components.html(html_code, height=400)

def show_authentication_section():
    """Show authentication UI (your existing auth code)"""
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

    # Check if current identity needs authentication
    needs_auth = False
    if st.session_state.identity == "sender" and not st.session_state.sender_authenticated:
        needs_auth = True
    elif st.session_state.identity == "receiver" and not st.session_state.receiver_authenticated:
        needs_auth = True

    if needs_auth:
        # Show authentication screen
        st.markdown(f"""
        <div class="auth-box">
            <h2>🔐 {st.session_state.identity.upper()} Authentication Required</h2>
            <p>Please authenticate with your face and fingerprint to continue</p>
        </div>
        """, unsafe_allow_html=True)

        col1, col2 = st.columns([2, 1])

        with col1:
            st.info(f"""
            **Authentication for {st.session_state.identity.upper()}:**
            
            1. **Face Recognition** - Look at camera
            2. **Fingerprint Scan** - Place finger on sensor
            
            **Requirements:**
            - Enrolled face template for **{st.session_state.identity}**
            - Enrolled fingerprint template for **{st.session_state.identity}**
            """)

            auth_mode = st.selectbox(
                "Authentication Mode:",
                ["Full", "Face", "Fingerprint"],
                index=0,
                key="auth_mode"
            )
            # Eavesdropping simulation (sender only, as sender initiates BB84)
            simulate_eavesdrop = False
            if st.session_state.identity == "sender":
                st.markdown("##### 🥷 Security Testing")
                simulate_eavesdrop = st.checkbox(
                    "Simulate QKD Eavesdropping Attack", 
                    help="Forces a 25% error rate on the quantum channel to trigger the BB84 eavesdropping alarm."
                )

            if st.button("🔓 Authenticate Now", type="primary", use_container_width=True, key="auth_start_btn"):
                with st.spinner(f"Authenticating as {st.session_state.identity}... Look at camera"):
                    result = authenticate(st.session_state.identity, auth_mode, simulate_eavesdrop)

                if result.get('success'):
                    session_id = result.get('session_id')
                    
                    # Store session based on identity
                    if st.session_state.identity == "sender":
                        st.session_state.sender_session_id = session_id
                        st.session_state.sender_authenticated = True
                    else:
                        st.session_state.receiver_session_id = session_id
                        st.session_state.receiver_authenticated = True
                    
                    st.session_state.session_id = session_id
                    st.session_state.key_fingerprint = result.get('key_fingerprint')

                    st.success(f"✅ {st.session_state.identity.upper()} Authentication Successful!")
                    
                    # Show confidence metrics
                    cols = st.columns(2)
                    with cols[0]:
                        st.metric("Face Confidence", f"{result.get('face_confidence', 0):.2%}")
                    with cols[1]:
                        st.metric("Fingerprint Confidence", f"{result.get('fingerprint_confidence', 0):.2%}")

                    st.rerun()
                else:
                    if result.get('eavesdropping_detected'):
                        st.error("🚨 **SECURITY ALERT:** " + result.get('message', 'Eavesdropping detected!'))
                        st.warning("The BB84 quantum channel detected an error rate exceeding the 15% safety threshold. Key exchange was aborted.")
                    else:
                        st.error(f"❌ Authentication Failed: {result.get('message', 'Unknown error')}")

        with col2:
            st.subheader("Enrollment Status")
            try:
                response = requests.get(f"{API_BASE}/enrollment/{st.session_state.identity}", timeout=5)
                if response.status_code == 200:
                    status = response.json()

                    if status['face_enrolled']:
                        st.success("✅ Face Enrolled")
                    else:
                        st.error("❌ Face Not Enrolled")
                        st.caption("Go to Enrollment tab to enroll")

                    if status['fingerprint_enrolled']:
                        st.success("✅ Fingerprint Enrolled")
                    else:
                        st.error("❌ Fingerprint Not Enrolled")
                        st.caption("Go to Enrollment tab to enroll")
            except Exception as e:
                st.error(f"Cannot check enrollment: {e}")
                
            st.divider()
            st.info("Continuous authentication will begin once you are successfully authenticated.")
    else:
        # Authenticated - show operations
        st.header(f"📁 {st.session_state.identity.upper()} Operations")

        if st.session_state.identity == "sender":
            # Check if file was already downloaded
            if st.session_state.get('sender_downloaded', False):
                st.success("🎉 Thank you! The encrypted payload has been downloaded successfully.")
                if st.button("Start New Transfer", key="sender_reset_btn"):
                    st.session_state.sender_downloaded = False
                    st.rerun()
                return

            col_main, col_auth = st.columns([2, 1])
            with col_main:
                # Sender: Encrypt and Send
                st.subheader("🔒 Encrypt & Send File")

                uploaded_file = st.file_uploader(
                    "Choose file to encrypt",
                    type=['txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'zip', 'json'],
                    help="Max file size: 100MB",
                    key="sender_file_upload"
                )

                compress = st.checkbox("Compress before encryption", value=True, key="sender_compress")

                if uploaded_file is not None:
                    col1, col2 = st.columns([1, 1])

                    with col1:
                        st.info(f"**File:** {uploaded_file.name}")
                        st.info(f"**Size:** {len(uploaded_file.getvalue()) / 1024:.2f} KB")
                        st.info(f"**Type:** {uploaded_file.type}")

                    with col2:
                        if st.button("🔐 Encrypt File", type="primary", use_container_width=True, key="sender_encrypt_btn"):
                            with st.spinner("Encrypting..."):
                                success, data, metadata = upload_and_encrypt(
                                    uploaded_file, 
                                    st.session_state.sender_session_id,
                                    compress
                                )

                            if success:
                                st.session_state.sender_encrypted_data = data
                                st.session_state.sender_encrypted_meta = metadata
                                st.session_state.sender_uploaded_name = uploaded_file.name
                            else:
                                st.error(f"❌ Encryption failed: {data}")

                        # If we have encrypted data, show it independently of the Encrypt button
                        if st.session_state.get('sender_encrypted_data') is not None:
                            st.success("✅ File encrypted successfully!")
                            
                            metadata = st.session_state.get('sender_encrypted_meta')
                            if metadata:
                                meta = json.loads(metadata)
                                st.json(meta)

                            output_filename = f"{st.session_state.sender_uploaded_name}.enc"
                            
                            def on_sender_download():
                                st.session_state.sender_downloaded = True
                                # Clear the payload from memory
                                st.session_state.sender_encrypted_data = None
                                
                            st.download_button(
                                label="⬇️ Download Encrypted File",
                                data=st.session_state.sender_encrypted_data,
                                file_name=output_filename,
                                mime="application/octet-stream",
                                key="sender_download_btn",
                                on_click=on_sender_download
                            )

                            st.info("📤 Encrypted! Now switch to Receiver mode to decrypt.")

            with col_auth:
                st.subheader("🛡️ Continuous Security")
                st.caption("Auto-capturing every 5 seconds")
                show_continuous_auth_widget()

        else:
            # Check if file was already downloaded
            if st.session_state.get('receiver_downloaded', False):
                st.success("🎉 Thank you! The decrypted payload has been downloaded successfully.")
                if st.button("Start New Transfer", key="receiver_reset_btn"):
                    st.session_state.receiver_downloaded = False
                    st.rerun()
                return

            col_main, col_auth = st.columns([2, 1])
            with col_main:
                # Receiver: Decrypt
                st.subheader("🔓 Decrypt Received File")

                encrypted_file = st.file_uploader(
                    "Choose encrypted file",
                    type=['enc'],
                    help="Upload .enc file from sender",
                    key="receiver_file_upload"
                )

            if encrypted_file is not None:
                col1, col2 = st.columns([1, 1])

                with col1:
                    st.info(f"**File:** {encrypted_file.name}")
                    st.info(f"**Size:** {len(encrypted_file.getvalue()) / 1024:.2f} KB")

                with col2:
                    if st.button("🔓 Decrypt File", type="primary", use_container_width=True, key="receiver_decrypt_btn"):
                        with st.spinner("Decrypting..."):
                            success, data, metadata = upload_and_decrypt(
                                encrypted_file,
                                st.session_state.receiver_session_id
                            )

                        if success:
                            st.session_state.receiver_decrypted_data = data
                            st.session_state.receiver_decrypted_meta = metadata
                            st.session_state.receiver_uploaded_name = encrypted_file.name
                        else:
                            st.error(f"❌ Decryption failed: {data}")

                    # If we have decrypted data, show it independently of the Decrypt button
                    if st.session_state.get('receiver_decrypted_data') is not None:
                        st.success("✅ File decrypted successfully!")

                        metadata = st.session_state.get('receiver_decrypted_meta')
                        if metadata:
                            meta = json.loads(metadata)
                            original_name = meta.get('original_name', 'decrypted_file')
                            st.json(meta)
                        else:
                            original_name = st.session_state.receiver_uploaded_name.replace('.enc', '')

                        def on_receiver_download():
                            st.session_state.receiver_downloaded = True
                            st.session_state.receiver_decrypted_data = None
                            
                        st.download_button(
                            label="⬇️ Download Decrypted File",
                            data=st.session_state.receiver_decrypted_data,
                            file_name=original_name,
                            mime="application/octet-stream",
                            key="receiver_download_btn",
                            on_click=on_receiver_download
                        )
                        
                        st.info("✅ Decryption complete!")

            with col_auth:
                st.subheader("🛡️ Continuous Security")
                st.caption("Auto-capturing every 5 seconds")
                show_continuous_auth_widget()

def main():
    # Header
    st.markdown(f'<div class="main-header">🔐 QKD Multimodal Secure Communication</div>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")

        sender_status = get_enrollment_status("sender")
        receiver_status = get_enrollment_status("receiver")

        # 1) Switch identity in top of the page
        st.subheader("Switch Identity")
        selected_identity = st.radio(
            "Select identity:",
            ["sender", "receiver"],
            index=0 if st.session_state.identity == "sender" else 1,
            key="identity_switch"
        )
        
        # Handle identity switch
        if selected_identity != st.session_state.identity:
            if selected_identity == "receiver":
                if not st.session_state.receiver_authenticated:
                    st.session_state.identity = "receiver"
                    st.warning("⚠️ Switching to Receiver - Authentication Required!")
                    st.rerun()
                else:
                    st.session_state.identity = "receiver"
                    st.success("Switched to Receiver (already authenticated)")
                    st.rerun()
            else:
                if not st.session_state.sender_authenticated:
                    st.session_state.identity = "sender"
                    st.warning("⚠️ Switching to Sender - Authentication Required!")
                    st.rerun()
                else:
                    st.session_state.identity = "sender"
                    st.success("Switched to Sender (already authenticated)")
                    st.rerun()

        st.divider()

        # 2) Enrollment page
        st.subheader("📝 Enrollment")
        enrollment_needed = False
        if sender_status and not sender_status.get('fully_enrolled', False):
            enrollment_needed = True
        if receiver_status and not receiver_status.get('fully_enrolled', False):
            enrollment_needed = True
        
        if enrollment_needed:
            st.warning("⚠️ Enrollment Required!")
            if st.button("📝 Go to Enrollment", type="primary", use_container_width=True, key="sidebar_enroll_btn"):
                st.session_state.current_page = "enrollment"
                st.rerun()
        else:
            st.success("✅ All Users Enrolled")
            if st.button("🏠 Main Application", use_container_width=True, key="sidebar_main_btn"):
                return_to_main_app()
                
        if st.button("📝 Open Enrollment Center", use_container_width=True, key="sidebar_external_enroll"):
            st.session_state.current_page = "enrollment"
            st.rerun()

        st.divider()

        # 3) Auth status
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

        # 4) Backend conn
        st.subheader("🌐 Backend Connection")
        if check_backend():
            st.success("🟢 Backend Connected")
        else:
            st.error("🔴 Backend Disconnected")

        st.divider()

        # 5) Logout page
        if st.button("🚪 Logout & Back to Login", type="secondary",
                     use_container_width=True, key="sidebar_logout"):
            st.session_state.sender_authenticated = False
            st.session_state.receiver_authenticated = False
            st.session_state.sender_session_id = None
            st.session_state.receiver_session_id = None
            st.session_state.session_id = None
            st.session_state.key_fingerprint = None
            st.markdown(
                '<meta http-equiv="refresh" content="1;url=http://localhost:8501">',
                unsafe_allow_html=True
            )
    
    # Main content based on page
    if st.session_state.current_page == "enrollment":
        show_enrollment_section()
    else:
        show_authentication_section()
    
if __name__ == "__main__":
    main()
