"""
QKD Multimodal Secure Communication - Enrollment Page
Dedicated page for enrolling sender and receiver biometrics
"""
import requests
from datetime import datetime

import streamlit as st

# Page config
st.set_page_config(
    page_title="QKD Enrollment",
    page_icon="📝",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration
BACKEND_URL = "http://localhost:8000"
API_BASE = f"{BACKEND_URL}"

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #11998e;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .enroll-box {
        background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        padding: 2rem;
        border-radius: 1rem;
        color: white;
        text-align: center;
        margin: 2rem 0;
    }
    .nav-button {
        background-color: #1f77b4;
        color: white;
        padding: 0.75rem 2rem;
        border-radius: 0.5rem;
        text-decoration: none;
        font-weight: bold;
        display: inline-block;
        margin: 0.5rem;
    }
    .nav-button:hover {
        background-color: #0d5a8a;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #28a745;
        margin: 1rem 0;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 5px solid #dc3545;
        margin: 1rem 0;
    }
    .stButton>button {
        width: 100%;
        border-radius: 0.5rem;
        height: 3rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Session state
if 'enrollment_status_message' not in st.session_state:
    st.session_state.enrollment_status_message = None
if 'enrollment_status_type' not in st.session_state:
    st.session_state.enrollment_status_type = None

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
    except:
        return None

def show_status_message():
    """Show enrollment status message"""
    if st.session_state.enrollment_status_message:
        if st.session_state.enrollment_status_type == "success":
            st.markdown(f'<div class="success-box"><h4>✅ Success</h4><p>{st.session_state.enrollment_status_message}</p></div>', unsafe_allow_html=True)
        elif st.session_state.enrollment_status_type == "error":
            st.markdown(f'<div class="error-box"><h4>❌ Error</h4><p>{st.session_state.enrollment_status_message}</p></div>', unsafe_allow_html=True)

def clear_status():
    """Clear status message"""
    st.session_state.enrollment_status_message = None
    st.session_state.enrollment_status_type = None

def main():
    # Header
    st.markdown('<div class="main-header">📝 Biometric Enrollment Center</div>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #666;">Enroll sender and receiver before starting secure communication</p>', unsafe_allow_html=True)
    
    # Navigation buttons at top
    st.subheader("🧭 Navigation")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🏠 Back to Login", use_container_width=True):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8500">', unsafe_allow_html=True)
            st.info("Redirecting to Login page... Click: http://localhost:8500")
    
    with col2:
        if st.button("📤 Go to Sender App", use_container_width=True):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
            st.info("Redirecting to Sender page... Click: http://localhost:8502")
    
    with col3:
        if st.button("🔄 Refresh This Page", use_container_width=True):
            st.rerun()
    
    st.divider()
    
    # Check backend
    if not check_backend():
        st.error("🔴 Backend Not Connected! Please start the backend server first.")
        st.info("Run: `cd backend && uvicorn main:app --host 0.0.0.0 --port 8000`")
        return
    
    st.success("🟢 Backend Connected")
    
    # Show any status messages
    show_status_message()
    
    # Enrollment Status Dashboard
    st.subheader("📊 Current Enrollment Status")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 👤 Sender")
        sender_status = get_enrollment_status("sender")
        
        if sender_status:
            face_ok = sender_status.get('face_enrolled', False)
            fp_ok = sender_status.get('fingerprint_enrolled', False)
            
            if face_ok:
                st.success("✅ Face Enrolled")
            else:
                st.error("❌ Face Not Enrolled")
            
            if fp_ok:
                st.success("✅ Fingerprint Enrolled")
            else:
                st.error("❌ Fingerprint Not Enrolled")
            
            if face_ok and fp_ok:
                st.markdown('<div class="success-box"><h4>🎉 Sender Fully Enrolled!</h4></div>', unsafe_allow_html=True)
        else:
            st.warning("⚠️ Cannot check status")
    
    with col2:
        st.markdown("### 👤 Receiver")
        receiver_status = get_enrollment_status("receiver")
        
        if receiver_status:
            face_ok = receiver_status.get('face_enrolled', False)
            fp_ok = receiver_status.get('fingerprint_enrolled', False)
            
            if face_ok:
                st.success("✅ Face Enrolled")
            else:
                st.error("❌ Face Not Enrolled")
            
            if fp_ok:
                st.success("✅ Fingerprint Enrolled")
            else:
                st.error("❌ Fingerprint Not Enrolled")
            
            if face_ok and fp_ok:
                st.markdown('<div class="success-box"><h4>🎉 Receiver Fully Enrolled!</h4></div>', unsafe_allow_html=True)
        else:
            st.warning("⚠️ Cannot check status")
    
    st.divider()
    
    # Enrollment Section
    st.subheader("🚀 Enroll User")
    
    # Select identity
    identity = st.radio(
        "Select user to enroll:",
        ["sender", "receiver"],
        horizontal=True,
        key="enroll_identity"
    )
    
    # Check current status
    current_status = get_enrollment_status(identity)
    already_enrolled = False
    if current_status:
        already_enrolled = current_status.get('fully_enrolled', False)
    
    if already_enrolled:
        st.info(f"ℹ️ **{identity.upper()}** is already enrolled. You can re-enroll to update templates.")
    
    # Face Enrollment Section
    st.markdown(f"### 📸 Step 1: Enroll Face for {identity.upper()}")
    st.warning("📸 Please ensure:\n- Good lighting on your face\n- Remove glasses/mask if possible\n- Look directly at camera")
    
    # Camera capture
    camera_image = st.camera_input(f"Capture face for {identity}", key=f"face_camera_{identity}")
    
    if camera_image is not None:
        st.image(camera_image, caption="Captured Face", use_column_width=True)
        
        col1, col2 = st.columns([1, 2])
        with col1:
            if st.button("↻ Retake Photo", key="retake_face"):
                st.rerun()
        with col2:
            if st.button("✅ Save Face Template", type="primary", key="save_face"):
                with st.spinner("Processing face enrollment..."):
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
                            st.session_state.enrollment_status_message = result.get('message', f'{identity} face enrolled successfully!')
                            st.session_state.enrollment_status_type = "success"
                            st.rerun()
                        else:
                            st.session_state.enrollment_status_message = result.get('message', 'Face enrollment failed')
                            st.session_state.enrollment_status_type = "error"
                            st.rerun()
                    except Exception as e:
                        st.session_state.enrollment_status_message = f"Error: {str(e)}"
                        st.session_state.enrollment_status_type = "error"
                        st.rerun()
    
    # Alternative: Upload photo
    with st.expander("📁 Or upload a photo instead"):
        uploaded_photo = st.file_uploader("Choose a photo", type=['jpg', 'jpeg', 'png'], key=f"upload_face_{identity}")
        if uploaded_photo is not None:
            st.image(uploaded_photo, caption="Uploaded Photo")
            if st.button("✅ Use This Photo", type="primary", key="upload_face_btn"):
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
                            st.session_state.enrollment_status_message = result.get('message', f'{identity} face enrolled!')
                            st.session_state.enrollment_status_type = "success"
                            st.rerun()
                        else:
                            st.session_state.enrollment_status_message = result.get('message', 'Failed')
                            st.session_state.enrollment_status_type = "error"
                            st.rerun()
                    except Exception as e:
                        st.session_state.enrollment_status_message = f"Error: {str(e)}"
                        st.session_state.enrollment_status_type = "error"
                        st.rerun()
    
    st.divider()
    
    # Fingerprint Enrollment Section
    st.markdown(f"### 🖐️ Step 2: Enroll Fingerprint for {identity.upper()}")
    st.warning("🖐️ Instructions:\n1. Place your finger on the sensor\n2. Hold for 2-3 seconds\n3. For hardware: lift and place 3 times")
    
    # Check sensor status
    try:
        response = requests.get(f"{API_BASE}/fingerprint/info", timeout=5)
        fp_info = response.json() if response.status_code == 200 else {"mode": "unknown"}
    except:
        fp_info = {"mode": "unknown"}
    
    if fp_info.get('mode') == 'simulation':
        st.info("ℹ️ Running in **Simulation Mode** (no hardware detected)")
    elif fp_info.get('mode') == 'hardware':
        st.success(f"✅ Hardware sensor detected on {fp_info.get('port', 'unknown')}")
    else:
        st.warning("⚠️ Cannot detect sensor status")
    
    if st.button("🖐️ Start Fingerprint Enrollment", type="primary", key="enroll_fp"):
        with st.spinner("Capturing fingerprint... Place finger on sensor"):
            try:
                response = requests.post(
                    f"{API_BASE}/enroll/fingerprint",
                    json={"identity": identity},
                    timeout=60
                )
                result = response.json()
                
                if result.get('success'):
                    st.session_state.enrollment_status_message = result.get('message', f'{identity} fingerprint enrolled!')
                    st.session_state.enrollment_status_type = "success"
                    st.rerun()
                else:
                    st.session_state.enrollment_status_message = result.get('message', 'Fingerprint enrollment failed')
                    st.session_state.enrollment_status_type = "error"
                    st.rerun()
            except Exception as e:
                st.session_state.enrollment_status_message = f"Error: {str(e)}"
                st.session_state.enrollment_status_type = "error"
                st.rerun()
    
    st.divider()
    
    # Bottom Navigation
    st.subheader("➡️ Go to Authentication Pages")
    
    # Check if both enrolled
    s_status = get_enrollment_status("sender")
    r_status = get_enrollment_status("receiver")
    s_fully = s_status.get('fully_enrolled', False) if s_status else False
    r_fully = r_status.get('fully_enrolled', False) if r_status else False
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("### Sender")
        if s_fully:
            st.success("✅ Sender enrolled and ready")
        else:
            st.error("❌ Sender not fully enrolled")
        
        if st.button("🔐 Go to Sender App", type="primary", use_container_width=True):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
            st.info("Redirecting... If not redirected, click: http://localhost:8502")
    
    with col2:
        st.markdown("### Receiver")
        if r_fully:
            st.success("✅ Receiver enrolled and ready")
        else:
            st.error("❌ Receiver not fully enrolled")
        
        if st.button("🔐 Go to Receiver App", type="primary", use_container_width=True):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
            st.info("Redirecting... If not redirected, click: http://localhost:8502")

    with col3:
        st.markdown("### Login Portal")
        st.info("Use the login page as your main entry point")
        if st.button("🏠 Back to Login", use_container_width=True):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8500">', unsafe_allow_html=True)
            st.info("Redirecting to Login → http://localhost:8500")

if __name__ == "__main__":
    main()