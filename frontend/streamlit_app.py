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

# Custom CSS — Premium dark theme
st.markdown("""
<style>
    /* ── Google Fonts ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    /* ── Global ── */
    #MainMenu { visibility: hidden; }
    footer     { visibility: hidden; }

    html, body, [class*="css"], .stApp {
        font-family: 'Inter', sans-serif !important;
        background: linear-gradient(135deg, #0f0c29 0%, #1a1a4e 50%, #24243e 100%) !important;
        color: #e2e8f0 !important;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: rgba(15,12,41,0.85) !important;
        border-right: 1px solid rgba(255,255,255,0.07) !important;
        backdrop-filter: blur(12px);
    }
    section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 { color: #ffffff !important; }

    /* ── Header ── */
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #667eea, #a78bfa, #38ef7d);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        text-align: center;
        margin-bottom: 0.3rem;
        letter-spacing: -0.5px;
    }
    .sub-header {
        font-size: 0.95rem;
        color: rgba(255,255,255,0.42);
        text-align: center;
        margin-bottom: 1.5rem;
        letter-spacing: 0.3px;
    }

    /* ── Auth box ── */
    .auth-box {
        background: linear-gradient(135deg, rgba(102,126,234,0.25) 0%, rgba(118,75,162,0.25) 100%);
        border: 1px solid rgba(102,126,234,0.4);
        padding: 2rem;
        border-radius: 1.2rem;
        color: white;
        text-align: center;
        margin: 1.5rem 0;
        backdrop-filter: blur(8px);
        box-shadow: 0 8px 32px rgba(102,126,234,0.15);
    }
    .auth-box h2 { color: #fff !important; font-weight: 800; }
    .auth-box p  { color: rgba(255,255,255,0.7) !important; }

    /* ── Enroll box ── */
    .enroll-box {
        background: linear-gradient(135deg, rgba(17,153,142,0.25) 0%, rgba(56,239,125,0.15) 100%);
        border: 1px solid rgba(56,239,125,0.3);
        padding: 2rem;
        border-radius: 1.2rem;
        color: white;
        text-align: center;
        margin: 1.5rem 0;
        backdrop-filter: blur(8px);
        box-shadow: 0 8px 32px rgba(17,153,142,0.15);
    }

    /* ── Status badges ── */
    .success-box {
        background: rgba(56,239,125,0.1);
        color: #6ee7b7;
        padding: 1rem 1.2rem;
        border-radius: 0.75rem;
        border-left: 4px solid #38ef7d;
        font-weight: 500;
        margin: 0.5rem 0;
    }
    .warning-box {
        background: rgba(251,191,36,0.1);
        color: #fcd34d;
        padding: 1rem 1.2rem;
        border-radius: 0.75rem;
        border-left: 4px solid #fbbf24;
        font-weight: 500;
        margin: 0.5rem 0;
    }
    .error-box {
        background: rgba(239,68,68,0.1);
        color: #fca5a5;
        padding: 1rem 1.2rem;
        border-radius: 0.75rem;
        border-left: 4px solid #ef4444;
        font-weight: 500;
        margin: 0.5rem 0;
    }
    .enroll-nav-box {
        background: rgba(102,126,234,0.1);
        border: 1px solid rgba(102,126,234,0.3);
        border-radius: 0.75rem;
        padding: 1rem;
        margin: 1rem 0;
    }

    /* ── Buttons ── */
    .stButton > button {
        width: 100% !important;
        border-radius: 0.75rem !important;
        height: 3rem !important;
        font-weight: 700 !important;
        font-size: 0.9rem !important;
        transition: all 0.2s ease !important;
        letter-spacing: 0.2px !important;
    }
    .stButton > button:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(102,126,234,0.35) !important;
    }
    button[kind="primary"] {
        background: linear-gradient(135deg, #667eea, #764ba2) !important;
        border: none !important;
        color: #fff !important;
    }

    /* ── Inputs ── */
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.06) !important;
        border: 1px solid rgba(255,255,255,0.12) !important;
        border-radius: 0.6rem !important;
        color: #e2e8f0 !important;
    }
    .stTextInput label, .stSelectbox label,
    .stFileUploader label, .stCheckbox label,
    .stRadio label {
        color: rgba(255,255,255,0.85) !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
    }

    /* ── Metrics ── */
    [data-testid="stMetric"] {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 0.75rem;
        padding: 0.75rem 1rem !important;
    }
    [data-testid="stMetricLabel"] { color: rgba(255,255,255,0.7) !important; font-size: 0.8rem !important; }
    [data-testid="stMetricValue"] { color: #ffffff !important; font-weight: 700 !important; }

    /* ── Divider ── */
    hr { border-color: rgba(255,255,255,0.08) !important; }

    /* ── Alerts ── */
    .stAlert { border-radius: 0.75rem !important; }

    /* ── Headings ── */
    h1, h2, h3 { color: #ffffff !important; font-weight: 700 !important; }
    h4, h5, h6 { color: #e2e8f0 !important; font-weight: 600 !important; }
    p, span, li { color: #e2e8f0 !important; }

    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: rgba(255,255,255,0.04) !important;
        border-radius: 0.6rem !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 5px; }
    ::-webkit-scrollbar-thumb { background: rgba(102,126,234,0.4); border-radius: 99px; }
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
    # Auto-detect role from login redirect query param (?role=sender/receiver)
    try:
        query_role = st.query_params.get("role", MODE)
        st.session_state.identity = query_role if query_role in ['sender', 'receiver'] else MODE
    except Exception:
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
if 'sender_downloaded' not in st.session_state:
    st.session_state.sender_downloaded = False
if 'receiver_downloaded' not in st.session_state:
    st.session_state.receiver_downloaded = False

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
    port = 8501 if st.session_state.identity == "Sender" else 8502
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
        identity = identity.lower()  # backend expects lowercase
        
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

            if st.button("🔓 Authenticate Now", type="primary", use_container_width=True, key="auth_start_btn"):
                with st.spinner(f"Authenticating as {st.session_state.identity}... Look at camera"):
                    result = authenticate(st.session_state.identity, auth_mode.lower())

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
    else:
        # Authenticated - show operations
        st.header(f"📁 {st.session_state.identity.upper()} Operations")

        # Continuous Face Authentication (Applies to both Sender and Receiver)
        import streamlit.components.v1 as components
        
        st.subheader("🛡️ Live Security Status")
        
        # Use raw HTML/JS for continuous background polling
        js_code = f"""
        <html>
        <body style="margin:0; padding:0; font-family: 'Inter', sans-serif;">
            <div id="auth-status" style="
                padding: 12px 16px;
                border-radius: 8px;
                background: #e0f2fe;
                color: #0369a1;
                border: 1px solid #bae6fd;
                font-size: 14px;
                font-weight: 600;
                display: flex;
                align-items: center;
                gap: 8px;
                transition: all 0.3s ease;
            ">
                <span class="pulse" style="
                    width: 8px; height: 8px; 
                    background: currentColor; 
                    border-radius: 50%;
                    display: inline-block;
                "></span>
                Initializing continuous {st.session_state.identity} verification...
            </div>

            <!-- Hidden elements for capture -->
            <video id="video" width="320" height="240" autoplay playsinline style="display:none;"></video>
            <canvas id="canvas" width="320" height="240" style="display:none;"></canvas>

            <script>
                const video = document.getElementById('video');
                const canvas = document.getElementById('canvas');
                const ctx = canvas.getContext('2d');
                const statusEl = document.getElementById('auth-status');
                
                let consecutiveFailures = 0;

                // Request camera
                navigator.mediaDevices.getUserMedia({{ video: true }})
                    .then(stream => {{
                        video.srcObject = stream;
                        statusEl.innerHTML = "✅ Camera connected. Continuous monitoring active.";
                    }})
                    .catch(err => {{
                        console.error("Camera access denied:", err);
                        statusEl.innerHTML = "⚠️ Camera access denied. Cannot verify {st.session_state.identity}.";
                        statusEl.style.background = "#fee2e2";
                        statusEl.style.color = "#b91c1c";
                        statusEl.style.borderColor = "#f87171";
                    }});
                    
                // Poll exactly every 5 seconds
                setInterval(() => {{
                    if (!video.videoWidth) return;
                    
                    // Capture frame
                    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                    const dataUrl = canvas.toDataURL('image/jpeg', 0.7); // 70% quality to save bandwidth
                    
                    // Send frame to continuous auth endpoint
                    fetch('{API_BASE}/authenticate/continuous', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            identity: '{st.session_state.identity}',
                            image: dataUrl
                        }})
                    }})
                    .then(res => res.json())
                    .then(data => {{
                        if (data.success) {{
                            consecutiveFailures = 0;
                            statusEl.innerHTML = "🟢 Live Face Verified (" + (data.confidence * 100).toFixed(1) + "%)";
                            statusEl.style.background = "#dcfce7";
                            statusEl.style.color = "#15803d";
                            statusEl.style.borderColor = "#86efac";
                        }} else {{
                            consecutiveFailures++;
                            statusEl.innerHTML = "🔴 Verification Failed: " + (data.message || "Face not recognized") + " (" + consecutiveFailures + " fails)";
                            statusEl.style.background = "#fee2e2";
                            statusEl.style.color = "#b91c1c";
                            statusEl.style.borderColor = "#f87171";
                            
                            // Optional: You can trigger a visible alert or logout if consecutiveFailures > threshold
                            if (consecutiveFailures > 5) {{
                                statusEl.innerHTML = "🚨 SECURITY BREACH: Authentication lost. Please re-authenticate.";
                            }}
                        }}
                    }})
                    .catch(err => {{
                        console.error("Auth polling error:", err);
                        statusEl.innerHTML = "⚠️ Backend connection error.";
                    }});
                }}, 5000);
            </script>
        </body>
        </html>
        """
        
        components.html(js_code, height=60)
        
        st.divider()

        if st.session_state.identity == "sender":
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
                    if st.button("🔐 Encrypt & Download", type="primary", use_container_width=True, key="sender_encrypt_btn"):
                        with st.spinner("Encrypting..."):
                            success, data, metadata = upload_and_encrypt(
                                uploaded_file, 
                                st.session_state.sender_session_id,
                                compress
                            )

                        if success:
                            st.success("✅ File encrypted successfully!")
                            st.session_state.sender_encrypted_data = data
                            st.session_state.sender_encrypted_filename = f"{uploaded_file.name}.enc"
                            if metadata:
                                st.session_state.sender_encrypted_meta = json.loads(metadata)
                            st.rerun()
                        else:
                            st.error(f"❌ Encryption failed: {data}")

            # Show Thank You page after successful encryption OR show download button
            if 'sender_encrypted_data' in st.session_state and st.session_state.sender_encrypted_data:
                if st.session_state.sender_downloaded:
                    # ── Thank You Page ──
                    st.markdown("""
                    <div style="
                        text-align:center;
                        padding: 3rem 2rem;
                        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
                        border-radius: 1.5rem;
                        color: white;
                        margin-top: 2rem;
                    ">
                        <div style="font-size: 4rem; margin-bottom: 1rem;">🎉</div>
                        <h1 style="font-size: 2.2rem; margin-bottom: 0.5rem;">Thank You!</h1>
                        <p style="font-size: 1.1rem; opacity: 0.92; margin-bottom: 0.5rem;">
                            Your encrypted file has been sent successfully.
                        </p>
                        <p style="font-size: 0.95rem; opacity: 0.8;">
                            The receiver can now decrypt it using their biometric credentials.
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                    st.balloons()
                    if st.button("🔄 Encrypt Another File", use_container_width=True, key="sender_reset_btn"):
                        del st.session_state.sender_encrypted_data
                        st.session_state.sender_downloaded = False
                        st.rerun()
                else:
                    # Show metadata + download button
                    if 'sender_encrypted_meta' in st.session_state:
                        st.json(st.session_state.sender_encrypted_meta)
                    out_fn = st.session_state.sender_encrypted_filename
                    st.download_button(
                        label="⬇️ Download Encrypted File",
                        data=st.session_state.sender_encrypted_data,
                        file_name=out_fn,
                        mime="application/octet-stream",
                        key="sender_download_btn",
                        on_click=lambda: st.session_state.update({"sender_downloaded": True})
                    )
                    st.info("📤 Click to download, then share with the receiver to decrypt.")

        else:
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
                    if st.button("🔓 Decrypt & Download", type="primary", use_container_width=True, key="receiver_decrypt_btn"):
                        with st.spinner("Decrypting..."):
                            success, data, metadata = upload_and_decrypt(
                                encrypted_file,
                                st.session_state.receiver_session_id
                            )

                        if success:
                            st.success("✅ File decrypted successfully!")
                            st.session_state.receiver_decrypted_data = data
                            if metadata:
                                meta = json.loads(metadata)
                                st.session_state.receiver_decrypted_name = meta.get('original_name', encrypted_file.name.replace('.enc', ''))
                                st.session_state.receiver_decrypted_meta = meta
                            else:
                                st.session_state.receiver_decrypted_name = encrypted_file.name.replace('.enc', '')
                            st.rerun()
                        else:
                            st.error(f"❌ Decryption failed: {data}")

            # Show Thank You page after successful decryption OR show download button
            if 'receiver_decrypted_data' in st.session_state and st.session_state.receiver_decrypted_data:
                if st.session_state.receiver_downloaded:
                    # ── Thank You Page ──
                    st.markdown("""
                    <div style="
                        text-align:center;
                        padding: 3rem 2rem;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        border-radius: 1.5rem;
                        color: white;
                        margin-top: 2rem;
                    ">
                        <div style="font-size: 4rem; margin-bottom: 1rem;">🔓</div>
                        <h1 style="font-size: 2.2rem; margin-bottom: 0.5rem;">Download Complete!</h1>
                        <p style="font-size: 1.1rem; opacity: 0.92; margin-bottom: 0.5rem;">
                            Your file has been securely decrypted.
                        </p>
                        <p style="font-size: 0.95rem; opacity: 0.8;">
                            Quantum-secured communication complete. Thank you!
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                    st.balloons()
                    if st.button("🔄 Decrypt Another File", use_container_width=True, key="receiver_reset_btn"):
                        del st.session_state.receiver_decrypted_data
                        st.session_state.receiver_downloaded = False
                        st.rerun()
                else:
                    # Show metadata + download button
                    if 'receiver_decrypted_meta' in st.session_state:
                        st.json(st.session_state.receiver_decrypted_meta)
                    out_fn = st.session_state.receiver_decrypted_name
                    st.download_button(
                        label="⬇️ Download Decrypted File",
                        data=st.session_state.receiver_decrypted_data,
                        file_name=out_fn,
                        mime="application/octet-stream",
                        key="receiver_download_btn",
                        on_click=lambda: st.session_state.update({"receiver_downloaded": True})
                    )
                    st.info("✅ Click to download your decrypted file.")

def main():
    # Header
    st.markdown(f'<div class="main-header">🔐 QKD Multimodal Secure Communication</div>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding: 1rem 0 0.5rem;">
            <div style="font-size:2rem;">🔐</div>
            <div style="font-size:1rem; font-weight:800; color:#f1f5f9; margin-top:0.2rem;">QKD Secure Comm</div>
            <div style="font-size:0.72rem; color:rgba(255,255,255,0.35); margin-top:0.1rem;">Quantum · Biometric · AES-256</div>
        </div>
        """, unsafe_allow_html=True)
        st.divider()

        sender_status = get_enrollment_status("sender")
        receiver_status = get_enrollment_status("receiver")

        # 1) Switch identity in top of the page
        st.subheader("Switch Identity")
        selected_identity = st.radio(
            "Select identity:",
            ["Sender", "Receiver"],
            index=0 if st.session_state.identity == "sender" else 1,
            key="identity_switch"
        )
        selected_identity = selected_identity.lower()  # normalize for comparisons
        
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
            st.rerun()
    
    # Main content based on page
    if st.session_state.current_page == "enrollment":
        show_enrollment_section()
    else:
        show_authentication_section()
    
if __name__ == "__main__":
    main()
