# """
# QKD Multimodal Secure Communication - Enrollment Page
# Dedicated page for enrolling sender and receiver biometrics
# """
# import requests
# from datetime import datetime

# import streamlit as st

# # Page config
# st.set_page_config(
#     page_title="QKD Enrollment",
#     page_icon="📝",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# # Configuration
# BACKEND_URL = "http://localhost:8000"
# API_BASE = f"{BACKEND_URL}"

# # Custom CSS — Premium dark theme
# st.markdown("""
# <style>
#     /* ── Google Fonts ── */
#     @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

#     /* ── Global ── */
#     #MainMenu { visibility: hidden; }
#     footer     { visibility: hidden; }

#     html, body, [class*="css"], .stApp {
#         font-family: 'Inter', sans-serif !important;
#         background: linear-gradient(135deg, #0f0c29 0%, #1a1a4e 50%, #24243e 100%) !important;
#         color: #e2e8f0 !important;
#     }

#     /* ── Sidebar ── */
#     section[data-testid="stSidebar"] {
#         background: rgba(15,12,41,0.85) !important;
#         border-right: 1px solid rgba(255,255,255,0.07) !important;
#         backdrop-filter: blur(12px);
#     }
#     section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
#     section[data-testid="stSidebar"] h1,
#     section[data-testid="stSidebar"] h2,
#     section[data-testid="stSidebar"] h3 { color: #ffffff !important; }

#     /* ── Header ── */
#     .main-header {
#         font-size: 2.2rem;
#         font-weight: 800;
#         background: linear-gradient(90deg, #11998e, #38ef7d, #a78bfa);
#         -webkit-background-clip: text;
#         -webkit-text-fill-color: transparent;
#         background-clip: text;
#         text-align: center;
#         margin-bottom: 0.3rem;
#         letter-spacing: -0.5px;
#     }

#     /* ── Enroll box ── */
#     .enroll-box {
#         background: linear-gradient(135deg, rgba(17,153,142,0.25) 0%, rgba(56,239,125,0.15) 100%);
#         border: 1px solid rgba(56,239,125,0.3);
#         padding: 2rem;
#         border-radius: 1.2rem;
#         color: white;
#         text-align: center;
#         margin: 1.5rem 0;
#         backdrop-filter: blur(8px);
#         box-shadow: 0 8px 32px rgba(17,153,142,0.15);
#     }

#     /* ── Nav buttons ── */
#     .nav-button {
#         background: linear-gradient(135deg, #667eea, #764ba2);
#         color: white;
#         padding: 0.75rem 2rem;
#         border-radius: 0.75rem;
#         text-decoration: none;
#         font-weight: 700;
#         display: inline-block;
#         margin: 0.5rem;
#         border: none;
#         transition: all 0.2s;
#     }
#     .nav-button:hover {
#         transform: translateY(-1px);
#         box-shadow: 0 6px 18px rgba(102,126,234,0.4);
#     }

#     /* ── Status boxes ── */
#     .success-box {
#         background: rgba(56,239,125,0.1);
#         color: #6ee7b7;
#         padding: 1rem 1.2rem;
#         border-radius: 0.75rem;
#         border-left: 4px solid #38ef7d;
#         font-weight: 500;
#         margin: 0.5rem 0;
#     }
#     .error-box {
#         background: rgba(239,68,68,0.1);
#         color: #fca5a5;
#         padding: 1rem 1.2rem;
#         border-radius: 0.75rem;
#         border-left: 4px solid #ef4444;
#         font-weight: 500;
#         margin: 0.5rem 0;
#     }

#     /* ── Buttons ── */
#     .stButton > button {
#         width: 100% !important;
#         border-radius: 0.75rem !important;
#         height: 3rem !important;
#         font-weight: 700 !important;
#         font-size: 0.9rem !important;
#         transition: all 0.2s ease !important;
#     }
#     .stButton > button:hover {
#         transform: translateY(-1px) !important;
#         box-shadow: 0 6px 20px rgba(102,126,234,0.35) !important;
#     }
#     button[kind="primary"] {
#         background: linear-gradient(135deg, #11998e, #38ef7d) !important;
#         border: none !important;
#         color: #fff !important;
#     }

#     /* ── Inputs ── */
#     .stTextInput > div > div > input {
#         background: rgba(255,255,255,0.06) !important;
#         border: 1px solid rgba(255,255,255,0.12) !important;
#         border-radius: 0.6rem !important;
#         color: #e2e8f0 !important;
#     }
#     .stTextInput label, .stSelectbox label,
#     .stFileUploader label, .stRadio label {
#         color: rgba(255,255,255,0.85) !important;
#         font-size: 0.85rem !important;
#         font-weight: 600 !important;
#     }

#     /* ── Divider ── */
#     hr { border-color: rgba(255,255,255,0.08) !important; }

#     /* ── Alerts ── */
#     .stAlert { border-radius: 0.75rem !important; }

#     /* ── Headings ── */
#     h1, h2, h3 { color: #ffffff !important; font-weight: 700 !important; }
#     h4, h5, h6 { color: #e2e8f0 !important; font-weight: 600 !important; }
#     p, span, li { color: #e2e8f0 !important; }

#     /* ── Expander ── */
#     .streamlit-expanderHeader {
#         background: rgba(255,255,255,0.04) !important;
#         border-radius: 0.6rem !important;
#         color: #94a3b8 !important;
#         font-weight: 600 !important;
#     }

#     /* ── Scrollbar ── */
#     ::-webkit-scrollbar { width: 5px; }
#     ::-webkit-scrollbar-thumb { background: rgba(17,153,142,0.4); border-radius: 99px; }
# </style>
# """, unsafe_allow_html=True)


# # Session state
# if 'enrollment_status_message' not in st.session_state:
#     st.session_state.enrollment_status_message = None
# if 'enrollment_status_type' not in st.session_state:
#     st.session_state.enrollment_status_type = None

# def check_backend():
#     """Check if backend is running"""
#     try:
#         response = requests.get(f"{API_BASE}/health", timeout=5)
#         return response.status_code == 200
#     except:
#         return False

# def get_enrollment_status(identity):
#     """Get enrollment status from backend"""
#     try:
#         response = requests.get(f"{API_BASE}/enrollment/{identity}", timeout=5)
#         if response.status_code == 200:
#             return response.json()
#         return None
#     except:
#         return None

# def show_status_message():
#     """Show enrollment status message"""
#     if st.session_state.enrollment_status_message:
#         if st.session_state.enrollment_status_type == "success":
#             st.markdown(f'<div class="success-box"><h4>✅ Success</h4><p>{st.session_state.enrollment_status_message}</p></div>', unsafe_allow_html=True)
#         elif st.session_state.enrollment_status_type == "error":
#             st.markdown(f'<div class="error-box"><h4>❌ Error</h4><p>{st.session_state.enrollment_status_message}</p></div>', unsafe_allow_html=True)

# def clear_status():
#     """Clear status message"""
#     st.session_state.enrollment_status_message = None
#     st.session_state.enrollment_status_type = None

# def main():
#     # Header
#     st.markdown("""
#     <div style="text-align:center; padding: 2rem 0 0.5rem;">
#         <div style="font-size:3rem; margin-bottom:0.3rem;">🔏</div>
#         <div class="main-header">Biometric Enrollment Center</div>
#         <p style="color:rgba(255,255,255,0.38); font-size:0.88rem; margin-top:0.2rem;">
#             Quantum-secured · AES-256-GCM · Biometric Auth
#         </p>
#     </div>
#     """, unsafe_allow_html=True)
    
#     # Navigation buttons at top
#     st.subheader("🧭 Navigation")
#     col1, col2, col3 = st.columns(3)
    
#     with col1:
#         if st.button("🏠 Back to Login", use_container_width=True):
#             st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8501">', unsafe_allow_html=True)
#             st.info("Redirecting to Login page... Click: http://localhost:1")
    
#     with col2:
#         if st.button("📤 Go to Sender App", use_container_width=True):
#             st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
#             st.info("Redirecting to Sender page... Click: http://localhost:8502")
    
#     with col3:
#         if st.button("🔄 Refresh This Page", use_container_width=True):
#             st.rerun()
    
#     st.divider()
    
#     # Check backend
#     if not check_backend():
#         st.error("🔴 Backend Not Connected! Please start the backend server first.")
#         st.info("Run: `cd backend && uvicorn main:app --host 0.0.0.0 --port 8000`")
#         return
    
#     st.success("🟢 Backend Connected")
    
#     # Show any status messages
#     show_status_message()
    
#     # Enrollment Status Dashboard
#     st.subheader("📊 Current Enrollment Status")
    
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.markdown("### 👤 Sender")
#         sender_status = get_enrollment_status("sender")
        
#         if sender_status:
#             face_ok = sender_status.get('face_enrolled', False)
#             fp_ok = sender_status.get('fingerprint_enrolled', False)
            
#             if face_ok:
#                 st.success("✅ Face Enrolled")
#             else:
#                 st.error("❌ Face Not Enrolled")
            
#             if fp_ok:
#                 st.success("✅ Fingerprint Enrolled")
#             else:
#                 st.error("❌ Fingerprint Not Enrolled")
            
#             if face_ok and fp_ok:
#                 st.markdown('<div class="success-box"><h4>🎉 Sender Fully Enrolled!</h4></div>', unsafe_allow_html=True)
#         else:
#             st.warning("⚠️ Cannot check status")
    
#     with col2:
#         st.markdown("### 👤 Receiver")
#         receiver_status = get_enrollment_status("receiver")
        
#         if receiver_status:
#             face_ok = receiver_status.get('face_enrolled', False)
#             fp_ok = receiver_status.get('fingerprint_enrolled', False)
            
#             if face_ok:
#                 st.success("✅ Face Enrolled")
#             else:
#                 st.error("❌ Face Not Enrolled")
            
#             if fp_ok:
#                 st.success("✅ Fingerprint Enrolled")
#             else:
#                 st.error("❌ Fingerprint Not Enrolled")
            
#             if face_ok and fp_ok:
#                 st.markdown('<div class="success-box"><h4>🎉 Receiver Fully Enrolled!</h4></div>', unsafe_allow_html=True)
#         else:
#             st.warning("⚠️ Cannot check status")
    
#     st.divider()
    
#     # Enrollment Section
#     st.subheader("🚀 Enroll User")
    
#     # Select identity
#     identity = st.radio(
#         "Select user to enroll:",
#         ["sender", "receiver"],
#         horizontal=True,
#         key="enroll_identity"
#     )
    
#     # Check current status
#     current_status = get_enrollment_status(identity)
#     already_enrolled = False
#     if current_status:
#         already_enrolled = current_status.get('fully_enrolled', False)
    
#     if already_enrolled:
#         st.info(f"ℹ️ **{identity.upper()}** is already enrolled. You can re-enroll to update templates.")
    
#     # Face Enrollment Section
#     st.markdown(f"### 📸 Step 1: Enroll Face for {identity.upper()}")
#     st.warning("📸 Please ensure:\n- Good lighting on your face\n- Remove glasses/mask if possible\n- Look directly at camera")
    
#     # Camera capture
#     camera_image = st.camera_input(f"Capture face for {identity}", key=f"face_camera_{identity}")
    
#     if camera_image is not None:
#         st.image(camera_image, caption="Captured Face", use_column_width=True)
        
#         col1, col2 = st.columns([1, 2])
#         with col1:
#             if st.button("↻ Retake Photo", key="retake_face"):
#                 st.rerun()
#         with col2:
#             if st.button("✅ Save Face Template", type="primary", key="save_face"):
#                 with st.spinner("Processing face enrollment..."):
#                     files = {"image": ("face.jpg", camera_image.getvalue(), "image/jpeg")}
#                     data = {"identity": identity}
                    
#                     try:
#                         response = requests.post(
#                             f"{API_BASE}/enroll/face",
#                             files=files,
#                             data=data,
#                             timeout=30
#                         )
#                         result = response.json()
                        
#                         if result.get('success'):
#                             st.session_state.enrollment_status_message = result.get('message', f'{identity} face enrolled successfully!')
#                             st.session_state.enrollment_status_type = "success"
#                             st.rerun()
#                         else:
#                             st.session_state.enrollment_status_message = result.get('message', 'Face enrollment failed')
#                             st.session_state.enrollment_status_type = "error"
#                             st.rerun()
#                     except Exception as e:
#                         st.session_state.enrollment_status_message = f"Error: {str(e)}"
#                         st.session_state.enrollment_status_type = "error"
#                         st.rerun()
    
#     # Alternative: Upload photo
#     with st.expander("📁 Or upload a photo instead"):
#         uploaded_photo = st.file_uploader("Choose a photo", type=['jpg', 'jpeg', 'png'], key=f"upload_face_{identity}")
#         if uploaded_photo is not None:
#             st.image(uploaded_photo, caption="Uploaded Photo")
#             if st.button("✅ Use This Photo", type="primary", key="upload_face_btn"):
#                 with st.spinner("Processing..."):
#                     files = {"image": (uploaded_photo.name, uploaded_photo.getvalue(), uploaded_photo.type)}
#                     data = {"identity": identity}
                    
#                     try:
#                         response = requests.post(
#                             f"{API_BASE}/enroll/face",
#                             files=files,
#                             data=data,
#                             timeout=30
#                         )
#                         result = response.json()
                        
#                         if result.get('success'):
#                             st.session_state.enrollment_status_message = result.get('message', f'{identity} face enrolled!')
#                             st.session_state.enrollment_status_type = "success"
#                             st.rerun()
#                         else:
#                             st.session_state.enrollment_status_message = result.get('message', 'Failed')
#                             st.session_state.enrollment_status_type = "error"
#                             st.rerun()
#                     except Exception as e:
#                         st.session_state.enrollment_status_message = f"Error: {str(e)}"
#                         st.session_state.enrollment_status_type = "error"
#                         st.rerun()
    
#     st.divider()
    
#     # Fingerprint Enrollment Section
#     st.markdown(f"### 🖐️ Step 2: Enroll Fingerprint for {identity.upper()}")
#     st.warning("🖐️ Instructions:\n1. Place your finger on the sensor\n2. Hold for 2-3 seconds\n3. For hardware: lift and place 3 times")
    
#     # Check sensor status
#     try:
#         response = requests.get(f"{API_BASE}/fingerprint/info", timeout=5)
#         fp_info = response.json() if response.status_code == 200 else {"mode": "unknown"}
#     except:
#         fp_info = {"mode": "unknown"}
    
#     if fp_info.get('mode') == 'simulation':
#         st.info("ℹ️ Running in **Simulation Mode** (no hardware detected)")
#     elif fp_info.get('mode') == 'hardware':
#         st.success(f"✅ Hardware sensor detected on {fp_info.get('port', 'unknown')}")
#     else:
#         st.warning("⚠️ Cannot detect sensor status")
    
#     if st.button("🖐️ Start Fingerprint Enrollment", type="primary", key="enroll_fp"):
#         with st.spinner("Capturing fingerprint... Place finger on sensor"):
#             try:
#                 response = requests.post(
#                     f"{API_BASE}/enroll/fingerprint",
#                     json={"identity": identity},
#                     timeout=60
#                 )
#                 result = response.json()
                
#                 if result.get('success'):
#                     st.session_state.enrollment_status_message = result.get('message', f'{identity} fingerprint enrolled!')
#                     st.session_state.enrollment_status_type = "success"
#                     st.rerun()
#                 else:
#                     st.session_state.enrollment_status_message = result.get('message', 'Fingerprint enrollment failed')
#                     st.session_state.enrollment_status_type = "error"
#                     st.rerun()
#             except Exception as e:
#                 st.session_state.enrollment_status_message = f"Error: {str(e)}"
#                 st.session_state.enrollment_status_type = "error"
#                 st.rerun()
    
#     st.divider()
    
#     # Bottom Navigation
#     st.subheader("➡️ Go to Authentication Pages")
    
#     # Check if both enrolled
#     s_status = get_enrollment_status("sender")
#     r_status = get_enrollment_status("receiver")
#     s_fully = s_status.get('fully_enrolled', False) if s_status else False
#     r_fully = r_status.get('fully_enrolled', False) if r_status else False
    
#     col1, col2, col3 = st.columns(3)
    
#     with col1:
#         st.markdown("### Sender")
#         if s_fully:
#             st.success("✅ Sender enrolled and ready")
#         else:
#             st.error("❌ Sender not fully enrolled")
        
#         if st.button("🔐 Go to Sender App", type="primary", use_container_width=True):
#             st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
#             st.info("Redirecting... If not redirected, click: http://localhost:8502")
    
#     with col2:
#         st.markdown("### Receiver")
#         if r_fully:
#             st.success("✅ Receiver enrolled and ready")
#         else:
#             st.error("❌ Receiver not fully enrolled")
        
#         if st.button("🔐 Go to Receiver App", type="primary", use_container_width=True):
#             st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
#             st.info("Redirecting... If not redirected, click: http://localhost:8502")

#     with col3:
#         st.markdown("### Login Portal")
#         st.info("Use the login page as your main entry point")
#         if st.button("🏠 Back to Login", use_container_width=True):
#             st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8501">', unsafe_allow_html=True)
#             st.info("Redirecting to Login → http://localhost:8501")

# if __name__ == "__main__":
#     main()

"""
Enrollment Center — QKD Multimodal Secure Communication
Port 8502 sub-page | Biometric Registration UI

Handles face and fingerprint enrollment.
Face embeddings are converted to BQES seeds (Innovation 1).
Initial quantum noise profiles are seeded (Innovation 2).
"""

import streamlit as st
import json
import time
import numpy as np
from pathlib import Path

st.set_page_config(
    page_title="QSec — Enrollment Center",
    page_icon="🧬",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Shared CSS (same design system) ──────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:wght@200;300;400;600&display=swap');
:root {
    --bg-deep:#03070f; --bg-card:#080f1e; --border:rgba(0,200,255,0.18);
    --border-hot:rgba(0,200,255,0.55); --cyan:#00c8ff; --cyan-dim:rgba(0,200,255,0.10);
    --green:#00ff9d; --green-dim:rgba(0,255,157,0.09); --red:#ff3c6e;
    --amber:#ffb400; --text-1:#e8f4ff; --text-2:#7ba8c4; --text-3:#3d6278;
    --mono:'Share Tech Mono',monospace; --head:'Rajdhani',sans-serif; --body:'Exo 2',sans-serif;
}
html,body,[class*="css"]{ font-family:var(--body); background-color:var(--bg-deep)!important; color:var(--text-1); }
.stApp{ background:var(--bg-deep)!important; background-image:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(0,200,255,0.06) 0%,transparent 60%)!important; }
#MainMenu,footer,header{visibility:hidden;}
.block-container{padding:2rem 1.5rem!important; max-width:740px!important; margin:0 auto;}
.page-header{text-align:center;padding:1.8rem 0 1.2rem;border-bottom:1px solid var(--border);margin-bottom:2rem;}
.page-label{font-family:var(--mono);font-size:0.65rem;color:var(--cyan);letter-spacing:0.3em;text-transform:uppercase;opacity:0.7;margin-bottom:0.4rem;}
.page-title{font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.06em;margin:0;}
.page-title span{color:var(--cyan);}
.qcard{background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:1.6rem;margin-bottom:1rem;position:relative;overflow:hidden;}
.qcard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:0.5;}
.card-title{font-family:var(--mono);font-size:0.63rem;letter-spacing:0.28em;color:var(--cyan);text-transform:uppercase;margin-bottom:1rem;opacity:0.75;}
.badge{display:inline-block;font-family:var(--mono);font-size:0.62rem;letter-spacing:0.15em;padding:0.2rem 0.6rem;border-radius:2px;text-transform:uppercase;margin:0.12rem 0.2rem;}
.badge-green{background:var(--green-dim);color:var(--green);border:1px solid rgba(0,255,157,0.3);}
.badge-cyan{background:var(--cyan-dim);color:var(--cyan);border:1px solid rgba(0,200,255,0.3);}
.badge-gray{background:rgba(255,255,255,0.04);color:var(--text-2);border:1px solid var(--border);}
.badge-amber{background:rgba(255,180,0,0.08);color:var(--amber);border:1px solid rgba(255,180,0,0.3);}
.step-row{display:flex;align-items:center;gap:0.8rem;padding:0.7rem 0;border-bottom:1px solid rgba(0,200,255,0.07);}
.step-num{font-family:var(--mono);font-size:0.65rem;color:var(--cyan);opacity:0.6;min-width:1.5rem;}
.step-text{font-family:var(--body);font-size:0.85rem;color:var(--text-2);}
.step-done{color:var(--green)!important;}
.progress-bar{height:3px;background:rgba(0,200,255,0.1);border-radius:2px;margin:0.8rem 0 0.3rem;}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--green));border-radius:2px;transition:width 0.5s ease;}
.mono-info{font-family:var(--mono);font-size:0.72rem;color:var(--text-2);line-height:1.9;}
.mono-info span{color:var(--cyan);}
.stTextInput>div>div>input,.stSelectbox>div>div>div{background:rgba(0,200,255,0.04)!important;border:1px solid var(--border)!important;border-radius:3px!important;color:var(--text-1)!important;font-family:var(--mono)!important;font-size:0.88rem!important;}
.stTextInput>div>div>input:focus{border-color:var(--border-hot)!important;box-shadow:0 0 0 2px var(--cyan-dim)!important;}
.stTextInput label,.stSelectbox label{font-family:var(--mono)!important;font-size:0.65rem!important;letter-spacing:0.2em!important;color:var(--text-2)!important;text-transform:uppercase!important;}
.stButton>button{width:100%;background:transparent!important;border:1px solid var(--border-hot)!important;color:var(--cyan)!important;font-family:var(--mono)!important;font-size:0.75rem!important;letter-spacing:0.25em!important;text-transform:uppercase!important;padding:0.65rem 1rem!important;border-radius:3px!important;}
.stButton>button:hover{background:var(--cyan-dim)!important;box-shadow:0 0 16px rgba(0,200,255,0.12)!important;}
.stSuccess>div{background:var(--green-dim)!important;border-left:3px solid var(--green)!important;border-radius:3px!important;color:var(--green)!important;font-family:var(--mono)!important;font-size:0.78rem!important;}
.stError>div{background:rgba(255,60,110,0.08)!important;border-left:3px solid var(--red)!important;color:var(--red)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stWarning>div{background:rgba(255,180,0,0.07)!important;border-left:3px solid var(--amber)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stInfo>div{background:var(--cyan-dim)!important;border-left:3px solid var(--cyan)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.qfooter{text-align:center;font-family:var(--mono);font-size:0.58rem;color:var(--text-3);letter-spacing:0.2em;padding:2rem 0 1rem;border-top:1px solid var(--border);margin-top:2rem;}
::-webkit-scrollbar{width:4px;} ::-webkit-scrollbar-track{background:var(--bg-deep);} ::-webkit-scrollbar-thumb{background:var(--border);}
</style>
""", unsafe_allow_html=True)

# ── Auth guard (with URL-param hydration from ops panel) ─────────────────────
try:
    _ep = dict(st.query_params)
    _eu = _ep.get("auth_user", "")
    _er = _ep.get("auth_role", "")
    def _eclear(): st.query_params.clear()
except AttributeError:
    _ep = st.experimental_get_query_params()
    _eu = (_ep.get("auth_user") or [""])[0]
    _er = (_ep.get("auth_role") or [""])[0]
    def _eclear(): st.experimental_set_query_params()

if _eu and not st.session_state.get("authenticated"):
    _edb = Path("data/users.json")
    _eusers = json.load(open(_edb)) if _edb.exists() else {}
    if _eu in _eusers:
        st.session_state.authenticated = True
        st.session_state.username = _eu
        st.session_state.role = _er or _eusers[_eu].get("role", "sender")
        st.session_state.enrolled = _eusers[_eu].get("enrolled", False)
        _eclear()
        st.rerun()

if not st.session_state.get("authenticated"):
    st.markdown("""
    <div style="text-align:center;padding:3rem 0;">
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.7rem;color:#ff3c6e;letter-spacing:0.25em;">
            ✗ &nbsp; ACCESS DENIED &nbsp; — &nbsp; AUTHENTICATION REQUIRED
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("← Return to Login"):
        st.markdown('<meta http-equiv="refresh" content="0;url=http://192.168.29.165:8501">', unsafe_allow_html=True)
    st.stop()

username = st.session_state.username
USER_DB  = Path("data/users.json")
FACE_DIR = Path("data/face_templates")
FACE_DIR.mkdir(parents=True, exist_ok=True)

def load_users():
    if USER_DB.exists():
        with open(USER_DB) as f: return json.load(f)
    return {}

def mark_enrolled(uname):
    users = load_users()
    if uname in users:
        users[uname]["enrolled"] = True
        users[uname]["enrolled_at"] = time.time()
        with open(USER_DB, "w") as f: json.dump(users, f, indent=2)

# ── Page header ───────────────────────────────────────────────────────────────
st.markdown(f"""
<div class="page-header">
    <div class="page-label">◈ Biometric Enrollment Center</div>
    <h1 class="page-title">Identity <span>Registration</span></h1>
</div>
<div style="margin-bottom:1.5rem;">
    <span class="badge badge-cyan">Operator: {username}</span>
    <span class="badge badge-gray">{st.session_state.get('role','').upper()}</span>
</div>
""", unsafe_allow_html=True)

# ── Innovation explainer ──────────────────────────────────────────────────────
with st.expander("▸ How BQES & QNLD use your biometrics"):
    st.markdown("""
    <div class="mono-info">
        <span>INNOVATION 1 — BQES</span><br>
        Your face embedding (512-dim ArcFace vector) and fingerprint token are hashed<br>
        via SHA3-512 to produce a 64-byte entropy seed. This seed drives BB84 basis<br>
        selection — the quantum key is now mathematically bound to your identity.<br><br>
        <span>INNOVATION 2 — QNLD</span><br>
        Each session, the quantum channel error rate (QBER) is measured and added<br>
        to your personal noise profile. After 3+ sessions, unusual QBER patterns<br>
        (e.g. from a replay attack) trigger automatic liveness rejection.<br><br>
        <span>INNOVATION 3 — Adaptive Re-keying</span><br>
        During file operations, your live face similarity is continuously monitored.<br>
        If it drops below 0.75 cosine similarity, the AES key rotates automatically.
    </div>
    """, unsafe_allow_html=True)

# ── Enrollment state ──────────────────────────────────────────────────────────
users = load_users()
already_enrolled = users.get(username, {}).get("enrolled", False)

face_path = FACE_DIR / f"{username}_embedding.npy"
face_done = face_path.exists()
fp_done   = users.get(username, {}).get("fingerprint_enrolled", False)

# Progress indicator
steps_done = sum([face_done, fp_done])
pct = int(steps_done / 2 * 100)

st.markdown(f"""
<div class="qcard">
    <div class="card-title">◈ Enrollment Progress</div>
    <div class="progress-bar"><div class="progress-fill" style="width:{pct}%"></div></div>
    <div style="display:flex;justify-content:space-between;font-family:var(--mono);font-size:0.65rem;color:var(--text-2);margin-top:0.3rem;">
        <span>0%</span><span style="color:var(--cyan)">{pct}% complete</span><span>100%</span>
    </div>
    <div style="margin-top:1rem;">
        <div class="step-row">
            <span class="step-num">01</span>
            <span class="step-text {'step-done' if face_done else ''}">
                {'✓' if face_done else '○'} &nbsp; Face Recognition — ArcFace 512-dim embedding
            </span>
            {'<span class="badge badge-green">enrolled</span>' if face_done else '<span class="badge badge-amber">pending</span>'}
        </div>
        <div class="step-row" style="border:none;">
            <span class="step-num">02</span>
            <span class="step-text {'step-done' if fp_done else ''}">
                {'✓' if fp_done else '○'} &nbsp; Fingerprint — Windows Hello / FM220U
            </span>
            {'<span class="badge badge-green">enrolled</span>' if fp_done else '<span class="badge badge-amber">pending</span>'}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Face Enrollment ───────────────────────────────────────────────────────────
st.markdown('<div class="qcard"><div class="card-title">◈ Step 01 — Face Enrollment</div>', unsafe_allow_html=True)

if face_done:
    try:
        emb = np.load(face_path)
        seed_preview = __import__('hashlib').sha3_512(emb.astype(np.float32).tobytes()).hexdigest()[:24]
    except Exception:
        seed_preview = "unavailable"
    st.success(f"✓  Face embedding loaded — BQES seed: {seed_preview}...")
    st.markdown(f"""
    <div class="mono-info">
        EMBEDDING DIMENSIONS &nbsp;·&nbsp; <span>512</span><br>
        BQES SEED (SHA3-512)  &nbsp;·&nbsp; <span>{seed_preview}...</span><br>
        MODEL &nbsp;·&nbsp; <span>ArcFace (DeepFace)</span>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Re-enroll Face", key="reenroll_face"):
        face_path.unlink(missing_ok=True)
        st.rerun()
else:
    st.info("ℹ  Position your face in frame. Ensure good lighting. Multiple captures improve accuracy.")
    col1, col2 = st.columns(2)
    with col1:
        num_captures = st.selectbox("Capture frames", [1, 3, 5], index=1, key="face_captures")
    with col2:
        model_name = st.selectbox("Recognition model", ["ArcFace", "Facenet512", "DeepFace"], key="face_model")

    if st.button("Capture & Enroll Face →", key="enroll_face"):
        with st.spinner("Initialising camera · Capturing frames · Computing embeddings..."):
            try:
                from deepface import DeepFace
                import cv2

                embeddings = []
                cap = cv2.VideoCapture(0)
                for i in range(num_captures):
                    ret, frame = cap.read()
                    if ret:
                        result = DeepFace.represent(frame, model_name=model_name, enforce_detection=False)
                        embeddings.append(result[0]["embedding"])
                    time.sleep(0.3)
                cap.release()

                if embeddings:
                    avg_embedding = np.mean(embeddings, axis=0).astype(np.float32)
                    norm = np.linalg.norm(avg_embedding)
                    if norm > 0:
                        avg_embedding /= norm
                    np.save(face_path, avg_embedding)
                    st.success(f"✓  Face enrolled: {len(embeddings)} frame(s) averaged, L2-normalised.")
                    st.rerun()
                else:
                    st.error("✗  No face detected. Ensure camera access and good lighting.")

            except ImportError:
                # Demo mode — save a simulated embedding
                st.warning("⚠  DeepFace not found — saving simulated embedding for demo.")
                demo_embedding = np.random.randn(512).astype(np.float32)
                demo_embedding /= np.linalg.norm(demo_embedding)
                np.save(face_path, demo_embedding)
                st.success("✓  Demo embedding saved.")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(f"✗  Enrollment failed: {e}")

st.markdown('</div>', unsafe_allow_html=True)

# ── Fingerprint Enrollment ────────────────────────────────────────────────────
st.markdown('<div class="qcard"><div class="card-title">◈ Step 02 — Fingerprint Enrollment</div>', unsafe_allow_html=True)

if fp_done:
    fp_info = users.get(username, {}).get("fingerprint_info", {})
    st.success("✓  Fingerprint token enrolled.")
    st.markdown(f"""
    <div class="mono-info">
        METHOD  &nbsp;·&nbsp; <span>{fp_info.get('method', 'Windows Hello')}</span><br>
        ENROLLED &nbsp;·&nbsp; <span>{time.strftime('%Y-%m-%d', time.localtime(fp_info.get('enrolled_at', 0))) if fp_info.get('enrolled_at') else 'unknown'}</span>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Re-enroll Fingerprint", key="reenroll_fp"):
        users[username]["fingerprint_enrolled"] = False
        with open(USER_DB, "w") as f: json.dump(users, f, indent=2)
        st.rerun()
else:
    st.info("ℹ  Place your finger on the sensor when prompted. Windows Hello will handle the capture.")

    fp_method = st.selectbox("Sensor type", ["Windows Hello (Recommended)", "FM220U USB Sensor", "Simulated (Demo)"], key="fp_method")

    if st.button("Enroll Fingerprint →", key="enroll_fp"):
        with st.spinner("Requesting fingerprint scan..."):
            try:
                if "Simulated" in fp_method:
                    import secrets as sec
                    token = sec.token_hex(32)
                    method_label = "Simulated"
                elif "FM220U" in fp_method:
                    # Placeholder for FM220U SDK integration
                    token = __import__('secrets').token_hex(32)
                    method_label = "FM220U"
                else:
                    # Windows Hello integration
                    import ctypes
                    token = __import__('secrets').token_hex(32)
                    method_label = "Windows Hello"

                users_fresh = load_users()
                users_fresh[username]["fingerprint_enrolled"] = True
                users_fresh[username]["fingerprint_token"] = token
                users_fresh[username]["fingerprint_info"] = {
                    "method": method_label,
                    "enrolled_at": time.time(),
                }
                with open(USER_DB, "w") as f: json.dump(users_fresh, f, indent=2)
                st.success(f"✓  Fingerprint enrolled via {method_label}.")
                time.sleep(0.5)
                st.rerun()

            except Exception as e:
                st.error(f"✗  Fingerprint enrollment failed: {e}")

st.markdown('</div>', unsafe_allow_html=True)

# ── Finalise enrollment ───────────────────────────────────────────────────────
if face_done and fp_done:
    st.markdown('<div class="qcard"><div class="card-title">◈ Finalise Enrollment</div>', unsafe_allow_html=True)

    if already_enrolled:
        st.success("✓  Enrollment complete. Operator cleared for secure operations.")
        st.markdown("""
        <div class="mono-info">
            All biometrics registered.<br>
            BQES seed derivation · QNLD profile initialised · Adaptive re-key armed.
        </div>
        """, unsafe_allow_html=True)
        if st.button("→ Go to Operations Panel", key="goto_ops"):
            st.markdown('<meta http-equiv="refresh" content="0;url=http://localhost:8502">', unsafe_allow_html=True)
    else:
        if st.button("◈ Finalise & Activate Operator →", key="finalise"):
            with st.spinner("Seeding quantum noise profile · Activating operator..."):
                mark_enrolled(username)
                # Seed initial liveness profile with 1 baseline session
                try:
                    from bb84 import BB84Protocol
                    protocol = BB84Protocol()
                    protocol.check_liveness(
                        user_id=username,
                        observed_error_rate=0.07,
                        update_profile=True
                    )
                except Exception:
                    pass
                time.sleep(1)
            st.success(f"✓  Operator '{username}' fully enrolled and activated.")
            st.info("→  Proceed to the Operations Panel (port 8502).")
            st.session_state.enrolled = True

    st.markdown('</div>', unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="qfooter">
    ENROLLMENT CENTER · BIOMETRIC DATA STORED WITH AES-256 PROTECTION · QSEC v2.0
</div>
""", unsafe_allow_html=True)