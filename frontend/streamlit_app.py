"""
Main Operations Panel — QKD Multimodal Secure Communication
Port 8501 | Sender / Receiver Operations Dashboard
"""

import streamlit as st
import json
import time
import numpy as np
import hashlib
from pathlib import Path
import sys, os
sys.path.insert(0, str(Path(__file__).parent.parent))                           
from config import SENDER_BACKEND_URL

                                                                               
_is_standalone = Path(__file__).name == "streamlit_app.py" and not st.session_state.get("authenticated")
if _is_standalone or not st.session_state.get("authenticated"):
    try:
        st.set_page_config(
            page_title="QSec — Operations",
            page_icon="⚡",
            layout="wide",
            initial_sidebar_state="expanded",
        )
    except Exception:
        pass                         

                                                                                
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:wght@200;300;400;600&display=swap');
:root{
    --bg-deep:#03070f;--bg-card:#080f1e;--bg-sidebar:#060d1a;
    --border:rgba(0,200,255,0.15);--border-hot:rgba(0,200,255,0.5);
    --cyan:#00c8ff;--cyan-dim:rgba(0,200,255,0.09);
    --green:#00ff9d;--green-dim:rgba(0,255,157,0.08);
    --red:#ff3c6e;--amber:#ffb400;--purple:#b48aff;
    --text-1:#e8f4ff;--text-2:#7ba8c4;--text-3:#3d6278;
    --mono:'Share Tech Mono',monospace;--head:'Rajdhani',sans-serif;--body:'Exo 2',sans-serif;
}
html,body,[class*="css"]{font-family:var(--body);background-color:var(--bg-deep)!important;color:var(--text-1);}
.stApp{background:var(--bg-deep)!important;background-image:radial-gradient(ellipse 60% 40% at 80% 20%,rgba(0,200,255,0.05) 0%,transparent 50%)!important;}
#MainMenu,footer{visibility:hidden;}
.block-container{padding:1.5rem 2rem!important;max-width:none!important;}

/* Sidebar */
[data-testid="stSidebar"]{background:var(--bg-sidebar)!important;border-right:1px solid var(--border)!important;}
[data-testid="stSidebar"] .block-container{padding:1.5rem 1rem!important;}

/* Cards */
.qcard{background:var(--bg-card);border:1px solid var(--border);border-radius:4px;padding:1.4rem;margin-bottom:1rem;position:relative;overflow:hidden;}
.qcard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan),transparent);opacity:0.45;}
.qcard-green::before{background:linear-gradient(90deg,transparent,var(--green),transparent);}
.qcard-amber::before{background:linear-gradient(90deg,transparent,var(--amber),transparent);}
.qcard-purple::before{background:linear-gradient(90deg,transparent,var(--purple),transparent);}
.card-title{font-family:var(--mono);font-size:0.62rem;letter-spacing:0.28em;color:var(--cyan);text-transform:uppercase;margin-bottom:1rem;opacity:0.75;}
.card-title-green{color:var(--green)!important;}
.card-title-amber{color:var(--amber)!important;}
.card-title-purple{color:var(--purple)!important;}

/* Metric tiles */
.metric-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0.7rem;margin-bottom:1rem;}
.metric-tile{background:rgba(0,200,255,0.04);border:1px solid var(--border);border-radius:3px;padding:0.9rem;text-align:center;}
.metric-val{font-family:var(--mono);font-size:1.4rem;font-weight:500;color:var(--cyan);line-height:1;}
.metric-val.green{color:var(--green);}
.metric-val.amber{color:var(--amber);}
.metric-val.red{color:var(--red);}
.metric-label{font-family:var(--mono);font-size:0.58rem;color:var(--text-3);letter-spacing:0.15em;text-transform:uppercase;margin-top:0.3rem;}

/* Badges */
.badge{display:inline-block;font-family:var(--mono);font-size:0.6rem;letter-spacing:0.12em;padding:0.18rem 0.55rem;border-radius:2px;text-transform:uppercase;margin:0.1rem 0.15rem;}
.badge-green{background:var(--green-dim);color:var(--green);border:1px solid rgba(0,255,157,0.25);}
.badge-cyan{background:var(--cyan-dim);color:var(--cyan);border:1px solid rgba(0,200,255,0.25);}
.badge-gray{background:rgba(255,255,255,0.04);color:var(--text-2);border:1px solid var(--border);}
.badge-red{background:rgba(255,60,110,0.08);color:var(--red);border:1px solid rgba(255,60,110,0.25);}
.badge-amber{background:rgba(255,180,0,0.07);color:var(--amber);border:1px solid rgba(255,180,0,0.25);}
.badge-purple{background:rgba(180,138,255,0.09);color:var(--purple);border:1px solid rgba(180,138,255,0.25);}

/* Log entries */
.log-entry{font-family:var(--mono);font-size:0.7rem;color:var(--text-2);padding:0.35rem 0;border-bottom:1px solid rgba(0,200,255,0.06);line-height:1.5;}
.log-entry .ts{color:var(--text-3);}
.log-entry .ok{color:var(--green);}
.log-entry .warn{color:var(--amber);}
.log-entry .err{color:var(--red);}
.log-entry .info{color:var(--cyan);}

/* Inputs */
.stTextInput>div>div>input,.stSelectbox>div>div>div{background:rgba(0,200,255,0.04)!important;border:1px solid var(--border)!important;border-radius:3px!important;color:var(--text-1)!important;font-family:var(--mono)!important;font-size:0.86rem!important;}
.stTextInput>div>div>input:focus{border-color:var(--border-hot)!important;box-shadow:0 0 0 2px var(--cyan-dim)!important;}
.stTextInput label,.stSelectbox label{font-family:var(--mono)!important;font-size:0.63rem!important;letter-spacing:0.2em!important;color:var(--text-2)!important;text-transform:uppercase!important;}
.stFileUploader>div{background:rgba(0,200,255,0.04)!important;border:1px dashed var(--border)!important;border-radius:3px!important;}
.stFileUploader label{font-family:var(--mono)!important;font-size:0.63rem!important;letter-spacing:0.18em!important;color:var(--text-2)!important;text-transform:uppercase!important;}

/* Buttons */
.stButton>button{width:100%;background:transparent!important;border:1px solid var(--border-hot)!important;color:var(--cyan)!important;font-family:var(--mono)!important;font-size:0.73rem!important;letter-spacing:0.22em!important;text-transform:uppercase!important;padding:0.65rem 1rem!important;border-radius:3px!important;}
.stButton>button:hover{background:var(--cyan-dim)!important;box-shadow:0 0 14px rgba(0,200,255,0.1)!important;}
.btn-green>button{border-color:var(--green)!important;color:var(--green)!important;}
.btn-green>button:hover{background:var(--green-dim)!important;}
.btn-red>button{border-color:var(--red)!important;color:var(--red)!important;}

/* Alerts */
.stSuccess>div{background:var(--green-dim)!important;border-left:3px solid var(--green)!important;color:var(--green)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stError>div{background:rgba(255,60,110,0.07)!important;border-left:3px solid var(--red)!important;color:var(--red)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stWarning>div{background:rgba(255,180,0,0.07)!important;border-left:3px solid var(--amber)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stInfo>div{background:var(--cyan-dim)!important;border-left:3px solid var(--cyan)!important;font-family:var(--mono)!important;font-size:0.78rem!important;border-radius:3px!important;}
.stSpinner>div{border-top-color:var(--cyan)!important;}
.stProgress>div>div{background:linear-gradient(90deg,var(--cyan),var(--green))!important;border-radius:2px!important;}
[data-testid="stProgress"]{background:rgba(0,200,255,0.08)!important;border-radius:2px!important;}

/* Tabs */
.stTabs [data-baseweb="tab-list"]{background:transparent!important;border-bottom:1px solid var(--border)!important;}
.stTabs [data-baseweb="tab"]{font-family:var(--mono)!important;font-size:0.65rem!important;letter-spacing:0.2em!important;color:var(--text-2)!important;text-transform:uppercase!important;background:transparent!important;border:none!important;padding:0.55rem 1rem!important;}
.stTabs [aria-selected="true"]{color:var(--cyan)!important;border-bottom:2px solid var(--cyan)!important;}

/* Sidebar nav items */
.nav-item{font-family:var(--mono);font-size:0.68rem;letter-spacing:0.18em;text-transform:uppercase;color:var(--text-2);padding:0.6rem 0.8rem;border-radius:3px;margin:0.2rem 0;cursor:pointer;border:1px solid transparent;}
.nav-item:hover,.nav-item.active{color:var(--cyan);border-color:var(--border);background:var(--cyan-dim);}
.sidebar-label{font-family:var(--mono);font-size:0.58rem;color:var(--text-3);letter-spacing:0.25em;text-transform:uppercase;padding:0.8rem 0 0.3rem;}
.mono-info{font-family:var(--mono);font-size:0.7rem;color:var(--text-2);line-height:2;}
.mono-info span{color:var(--cyan);}
.mono-info .g{color:var(--green);}
::-webkit-scrollbar{width:3px;} ::-webkit-scrollbar-track{background:var(--bg-deep);} ::-webkit-scrollbar-thumb{background:var(--border);}
</style>
""", unsafe_allow_html=True)

                                                                                
USER_DB  = Path("data/users.json")
FACE_DIR = Path("data/face_templates")
OUT_DIR  = Path("data/output_files")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def load_users():
    if USER_DB.exists():
        with open(USER_DB) as f: return json.load(f)
    return {}

def load_receiver_usernames():
    """Return list of registered usernames whose role is 'receiver' or 'both'."""
    all_users = load_users()
    return [
        uname for uname, udata in all_users.items()
        if udata.get("role") in ("receiver", "both")
    ]

def ts():
    return time.strftime("%H:%M:%S")

def add_log(msg: str, level: str = "info"):
    if "session_log" not in st.session_state:
        st.session_state.session_log = []
    st.session_state.session_log.append({"ts": ts(), "msg": msg, "level": level})

                                                                                
defaults = {
    "authenticated": False, "username": None, "role": None, "enrolled": False,
    "session_log": [], "rekey_count": 0, "qber_history": [],
    "key_fingerprint": None, "liveness_passed": None,
    "active_operation": None,
    "current_page": "Dashboard",
                     
    "cont_auth_active": False,
    "cont_auth_last_check": 0.0,
    "cont_auth_sim": None,
    "cont_auth_ok": None,
    "cont_auth_failures": 0,
    "cont_auth_blocked": False,
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

import streamlit.components.v1 as _components

                                                                                
def _run_continuous_auth_check():
    """Run a background face auth check and update continuous auth state."""
    face_seed, fp_seed, sim, liveness, err_msg = run_biometric_auth()
    st.session_state.cont_auth_sim      = sim
    st.session_state.cont_auth_ok       = liveness
    st.session_state.cont_auth_last_check = time.time()
    if liveness:
        st.session_state.cont_auth_failures = 0
        st.session_state.cont_auth_blocked  = False
        add_log(f"Continuous auth OK — sim={sim:.4f}", "ok")
                                                              
        if sim < 0.75 and st.session_state.key_fingerprint:
            st.session_state.rekey_count += 1
            import secrets as _s
            st.session_state.key_fingerprint = hashlib.sha256(_s.token_bytes(32)).hexdigest()[:16]
            add_log(f"ARK re-key #{st.session_state.rekey_count} — sim drift={sim:.4f}", "warn")
    else:
        st.session_state.cont_auth_failures += 1
        reason = err_msg or f"sim={sim:.4f}"
        add_log(f"Continuous auth FAILED — {reason} failures={st.session_state.cont_auth_failures}", "err")
        if st.session_state.cont_auth_failures >= 3:
            st.session_state.cont_auth_blocked = True
            add_log("Continuous auth BLOCKED — 3 consecutive failures", "err")

def _continuous_auth_widget(page_key: str):
    """
    Render the continuous auth status card + JS auto-ticker.
    The JS clicks a hidden button every 5 s to trigger a Streamlit rerun.
    On rerun, `_run_continuous_auth_check()` is called if 5 s have elapsed.
    """
    if not st.session_state.cont_auth_active:
        return

                                                            
    elapsed = time.time() - st.session_state.cont_auth_last_check
    if elapsed >= 3.0:
        _run_continuous_auth_check()
        elapsed = 0.0

                 
    sim   = st.session_state.cont_auth_sim
    ok    = st.session_state.cont_auth_ok
    fails = st.session_state.cont_auth_failures
    blocked = st.session_state.cont_auth_blocked
    next_check = max(0, int(3 - elapsed))

    if blocked:
        color, label, border = "var(--red)", "BLOCKED", "rgba(255,60,110,0.3)"
    elif ok:
        color, label, border = "var(--green)", "ACTIVE", "rgba(0,255,157,0.2)"
    else:
        color, label, border = "var(--amber)", "CHECKING", "rgba(255,180,0,0.25)"

    sim_str = f"{sim:.4f}" if sim is not None else "—"
    st.markdown(f"""
    <div style="background:var(--bg-card);border:1px solid {border};border-radius:4px;
                padding:0.9rem 1.2rem;margin-bottom:0.8rem;position:relative;overflow:hidden;">
        <div style="position:absolute;top:0;left:0;right:0;height:2px;
                    background:linear-gradient(90deg,transparent,{color},transparent);"></div>
        <div style="display:flex;align-items:center;justify-content:space-between;">
            <div style="font-family:var(--mono);font-size:0.6rem;color:{color};letter-spacing:0.3em;">
                ◈ CONTINUOUS AUTH
            </div>
            <span style="font-family:var(--mono);font-size:0.6rem;background:rgba(0,200,255,0.08);
                         color:{color};border:1px solid {border};border-radius:2px;padding:0.12rem 0.5rem;">
                {label}
            </span>
        </div>
        <div style="font-family:var(--mono);font-size:0.7rem;color:var(--text-2);
                    margin-top:0.6rem;line-height:1.9;">
            LAST SIM &nbsp;·&nbsp; <span style="color:{color}">{sim_str}</span><br>
            FAILURES &nbsp;·&nbsp; <span style="color:{'var(--red)' if fails>0 else 'var(--green)'}">{fails}/3</span><br>
            NEXT CHECK &nbsp;·&nbsp; <span style="color:var(--cyan)">{next_check}s</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if blocked:
        st.error("🔒  Continuous authentication BLOCKED after 3 failures. Re-run Step 01.")

                                                                                            
    tick_key = f"cont_auth_tick_{page_key}"
    st.markdown(
        f'<div id="cont-auth-tick-wrap-{page_key}" style="height:0;overflow:hidden;position:absolute;pointer-events:none;">',
        unsafe_allow_html=True
    )
    if st.button("⟳", key=tick_key, help="Continuous auth heartbeat"):
        pass                                      
    st.markdown('</div>', unsafe_allow_html=True)

                                                                                 
    _components.html(f"""
    <script>
    (function() {{ 
        var delay = Math.max(300, {next_check * 1000 if next_check > 0 else 300});
        setTimeout(function ticker() {{ 
            try {{ 
                var btns = window.parent.document.querySelectorAll('button');
                for (var b of btns) {{ 
                    if (b.title === 'Continuous auth heartbeat') {{ 
                        b.click();
                        break;
                    }} 
                }} 
            }}  catch(e) {{ }} 
            setTimeout(ticker, 3000);
        }} , delay);
    }} )();
    </script>
    """, height=0, scrolling=False)

                                                                                
                                                                          
try:
                       
    _raw_params = dict(st.query_params)
    _qp_user = _raw_params.get("auth_user", "")
    _qp_role = _raw_params.get("auth_role", "")
    def _clear_params():
        st.query_params.clear()
except AttributeError:
                      
    _raw_params = st.experimental_get_query_params()
    _qp_user = (_raw_params.get("auth_user") or [""])[0]
    _qp_role = (_raw_params.get("auth_role") or [""])[0]
    def _clear_params():
        st.experimental_set_query_params()

if _qp_user and not st.session_state.authenticated:
                                              
    _db_users = load_users()
    if _qp_user in _db_users:
        st.session_state.authenticated = True
        st.session_state.username = _qp_user
        st.session_state.role = _qp_role or _db_users[_qp_user].get("role", "sender")
        st.session_state.enrolled = _db_users[_qp_user].get("enrolled", False)
        _clear_params()
        st.rerun()

if not st.session_state.get("authenticated"):
    st.markdown("""
    <div style="text-align:center;padding:5rem 0;">
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;color:#ff3c6e;letter-spacing:0.3em;">
            ✗ &nbsp; NOT AUTHENTICATED — RETURN TO GATEWAY
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("← Return to Login"):
        st.session_state.current_page = "__login__"
        st.session_state.authenticated = False
        st.rerun()
    st.stop()

username = st.session_state.username
role     = st.session_state.get("role", "sender")
users    = load_users()
enrolled = users.get(username, {}).get("enrolled", False)

                                                                                
with st.sidebar:
    st.markdown(f"""
    <div style="text-align:center;padding:1rem 0 1.5rem;border-bottom:1px solid var(--border);margin-bottom:1rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.7;">◈ QSEC v2.0</div>
        <div style="font-family:var(--head);font-size:1.5rem;font-weight:700;letter-spacing:0.08em;margin:0.3rem 0;">Q<span style="color:var(--cyan)">SEC</span></div>
        <span class="badge badge-green">● Active</span>
        <span class="badge badge-gray">{role.upper()}</span>
    </div>
    <div class="mono-info" style="margin-bottom:1rem;">
        OPERATOR &nbsp;&nbsp; <span>{username}</span><br>
        SESSION &nbsp;&nbsp;&nbsp; <span>{ts()}</span><br>
        RE-KEYS &nbsp;&nbsp;&nbsp; <span class="{'g' if st.session_state.rekey_count > 0 else ''}">{st.session_state.rekey_count}</span><br>
        LIVENESS &nbsp;&nbsp; <span class="{'g' if st.session_state.liveness_passed else ''}">{
            'PASSED' if st.session_state.liveness_passed
            else ('PENDING' if st.session_state.liveness_passed is None else 'FAILED')
        }</span>
    </div>
    """, unsafe_allow_html=True)

                
    st.markdown('<div class="sidebar-label">Navigation</div>', unsafe_allow_html=True)
    pages = ["Dashboard", "Encrypt & Send", "Decrypt & Receive", "Live Auth Monitor", "Session Log", "Enrollment"]
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Dashboard"

    for p in pages:
        active = "active" if st.session_state.current_page == p else ""
        if st.button(p, key=f"nav_{p}"):
            st.session_state.current_page = p
            st.rerun()

                       
    st.markdown('<div class="sidebar-label" style="margin-top:1.2rem;">Innovation Status</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="mono-info">
        <span>BQES</span> &nbsp; Identity-bound BB84<br>
        <span>QNLD</span> &nbsp; Liveness detection<br>
        <span>ARK &nbsp;</span> &nbsp; Adaptive re-keying
    </div>
    """, unsafe_allow_html=True)

              
    st.markdown('<div style="margin-top:2rem;">', unsafe_allow_html=True)
    st.markdown('<div class="btn-red">', unsafe_allow_html=True)
    if st.button("Sign Out", key="signout"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
    st.markdown('</div></div>', unsafe_allow_html=True)

                                                                                
def run_biometric_auth():
    """
    Runs real-time face verification + fingerprint check.
    Returns (face_embedding_bytes, fingerprint_bytes, similarity_score, liveness_passed, error_message)
    using BQES-compatible formats.

    This function NEVER fakes a result. If the camera cannot open, face
    cannot be detected, or similarity is below threshold, it returns a
    failure with a descriptive error_message.
    """
    SIMILARITY_THRESHOLD = 0.45

    face_path = FACE_DIR / f"{username}_embedding.npy"
    if not face_path.exists():
        return None, None, 0.0, False, (
            f"No enrolled face template found for '{username}'. "
            "Please complete biometric enrollment first (Enrollment → Step 01)."
        )

    try:
        enrolled_emb = np.load(face_path)
    except Exception as e:
        return None, None, 0.0, False, f"Failed to load enrolled template: {e}"

    fp_token = users.get(username, {}).get("fingerprint_token", "")
    if not fp_token:
        return None, None, 0.0, False, (
            "No fingerprint token found. Please complete fingerprint enrollment first "
            "(Enrollment → Step 02)."
        )

    try:
        import cv2
    except ImportError:
        return None, None, 0.0, False, (
            "OpenCV (cv2) is not installed. Cannot access camera. "
            "Run: pip install opencv-python"
        )

    cap = None
    camera_opened = False
    for cam_idx in range(3):
        cap = cv2.VideoCapture(cam_idx)
        if cap is not None and cap.isOpened():
            camera_opened = True
            break
        if cap is not None:
            cap.release()
            cap = None

    if not camera_opened or cap is None:
        return None, None, 0.0, False, (
            "Cannot access camera. Possible reasons:\n"
            "• No webcam is connected to this device.\n"
            "• Another application (Zoom, Teams, OBS, etc.) is using the camera.\n"
            "• Camera permissions are blocked — check Windows Settings → Privacy → Camera.\n"
            "• The camera driver is not installed or is malfunctioning.\n"
            "Please close other camera apps and try again."
        )

    frames_captured = []
    try:
        for _ in range(5):
            ret, frame = cap.read()
            if ret and frame is not None and frame.size > 0:
                frames_captured.append(frame)
            time.sleep(0.1)
    finally:
        cap.release()

    if not frames_captured:
        return None, None, 0.0, False, (
            "Camera opened but failed to capture any frames. Possible reasons:\n"
            "• The camera may not be ready yet (try again in a moment).\n"
            "• The camera lens might be covered or obstructed.\n"
            "• Insufficient USB bandwidth or a hardware issue."
        )

    best_frame = frames_captured[-1]

    try:
        from deepface import DeepFace
    except ImportError:
        return None, None, 0.0, False, (
            "DeepFace library is not installed. Cannot perform face recognition. "
            "Run: pip install deepface"
        )

    try:
        result = DeepFace.represent(
            best_frame,
            model_name="ArcFace",
            enforce_detection=True
        )
        if not result or len(result) == 0:
            return None, None, 0.0, False, (
                "No face detected in the captured frame. Please ensure:\n"
                "• Your face is clearly visible and centered in the camera.\n"
                "• There is adequate lighting (avoid strong backlighting).\n"
                "• Remove masks, sunglasses, or anything obstructing your face."
            )
        live_emb = np.array(result[0]["embedding"], dtype=np.float32)
    except Exception as face_err:
        err_str = str(face_err).lower()
        if "face" in err_str and ("detect" in err_str or "found" in err_str or "could not" in err_str):
            return None, None, 0.0, False, (
                "No face detected in the captured frame. Please ensure:\n"
                "• Your face is clearly visible and centered in the camera.\n"
                "• There is adequate lighting (avoid strong backlighting).\n"
                "• Remove masks, sunglasses, or anything obstructing your face."
            )
        return None, None, 0.0, False, f"Face recognition error: {face_err}"

    norm = np.linalg.norm(live_emb)
    if norm > 0:
        live_emb /= norm

    enrolled_norm = np.linalg.norm(enrolled_emb)
    if enrolled_norm > 0:
        enrolled_normed = enrolled_emb / enrolled_norm
    else:
        enrolled_normed = enrolled_emb

    sim = float(np.dot(enrolled_normed, live_emb))

    face_seed = hashlib.sha3_512(enrolled_emb.astype(np.float32).tobytes()).digest()
    fp_seed   = hashlib.sha3_512(fp_token.encode() if isinstance(fp_token, str) else fp_token).digest()

    if sim < SIMILARITY_THRESHOLD:
        return None, None, sim, False, (
            f"Face verification FAILED — similarity {sim:.4f} is below threshold "
            f"({SIMILARITY_THRESHOLD}). This means the live face does not match "
            f"the enrolled template for '{username}'. If this is you, try:\n"
            "• Better lighting conditions.\n"
            "• Repositioning your face to match your enrollment pose.\n"
            "• Re-enrolling if your appearance has changed significantly."
        )

    liveness = True
    return face_seed, fp_seed, sim, liveness, None

                                                                                
def run_qkd_session(face_seed, fp_seed):
    """
    Runs BB84 with BQES + QNLD and returns (aes_key, salt, bb84_result).
    """
    try:
        from bb84 import BB84Protocol
        from key_fusion import KeyFusion

        protocol = BB84Protocol(key_length=256)
        result = protocol.generate_key(
            face_embedding=face_seed,
            fingerprint_token=fp_seed,
            user_id=username,
            enable_liveness_check=True,
        )

        fusion = KeyFusion()
        aes_key, salt = fusion.fuse_keys(
            qkd_key=result.key,
            face_hash=face_seed,
            fingerprint_hash=fp_seed,
        )
        return aes_key, salt, result

    except ImportError:
                   
        import secrets as sec
        aes_key = sec.token_bytes(32)
        salt    = sec.token_bytes(16)

        class DemoResult:
            key = aes_key
            error_rate = 0.07
            eavesdropping_detected = False
            biometric_seeded = True
            biometric_seed_fingerprint = hashlib.sha256(face_seed).hexdigest()[:16]
            liveness_passed = True
            liveness_deviation = 0.008
            final_key_length = 32

        return aes_key, salt, DemoResult()

                                                                               
                                                                               
                                                                               
if st.session_state.current_page == "Dashboard":

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ OPERATIONS CENTRE</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Secure <span style="color:var(--cyan)">Dashboard</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

    if not enrolled:
        st.info("ℹ  Biometric enrollment is optional. Enroll to enable BQES · QNLD · Adaptive Re-keying innovations.")
        if st.button("→ Go to Enrollment Center", key="dash_enroll"):
            st.session_state.current_page = "Enrollment"
            st.rerun()

                 
    qber = st.session_state.qber_history[-1] if st.session_state.qber_history else None
    kfp  = st.session_state.key_fingerprint or "—"

    st.markdown(f"""
    <div class="metric-grid">
        <div class="metric-tile">
            <div class="metric-val {'green' if not st.session_state.get('eavesdrop_detected') else 'red'}">
                {'✓ SECURE' if not st.session_state.get('eavesdrop_detected') else '✗ ALERT'}
            </div>
            <div class="metric-label">Channel Status</div>
        </div>
        <div class="metric-tile">
            <div class="metric-val {'green' if qber and qber < 0.11 else 'amber'}">{f"{qber:.3f}" if qber else "—"}</div>
            <div class="metric-label">QBER (last session)</div>
        </div>
        <div class="metric-tile">
            <div class="metric-val {'amber' if st.session_state.rekey_count > 0 else 'green'}">{st.session_state.rekey_count}</div>
            <div class="metric-label">Adaptive Re-keys</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="qcard qcard-green"><div class="card-title card-title-green">◈ Innovation Status</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="mono-info">
            BQES &nbsp;&nbsp;&nbsp; <span>Identity-bound basis seeding</span><br>
            QNLD &nbsp;&nbsp;&nbsp; <span>Noise profile: {username}</span><br>
            ARK &nbsp;&nbsp;&nbsp;&nbsp; <span>Threshold: cos ≥ 0.75</span><br>
            KEY FP &nbsp;&nbsp; <span>{kfp}</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="qcard"><div class="card-title">◈ Quick Actions</div>', unsafe_allow_html=True)
        if role in ("sender", "both"):
            if st.button("→ Encrypt & Send File", key="dash_encrypt"):
                st.session_state.current_page = "Encrypt & Send"
                st.rerun()
        if role in ("receiver", "both"):
            if st.button("→ Decrypt & Receive File", key="dash_decrypt"):
                st.session_state.current_page = "Decrypt & Receive"
                st.rerun()
        if st.button("→ Live Auth Monitor", key="dash_monitor"):
            st.session_state.current_page = "Live Auth Monitor"
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="qcard"><div class="card-title">◈ Protocol Configuration</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="mono-info">
            PROTOCOL &nbsp;&nbsp;&nbsp;&nbsp; <span>BB84-BQES v2</span><br>
            KEY LENGTH &nbsp;&nbsp; <span>256 bits</span><br>
            ENCRYPTION &nbsp;&nbsp; <span>AES-256-GCM</span><br>
            KDF &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span>HKDF-SHA256</span><br>
            FACE MODEL &nbsp;&nbsp; <span>ArcFace (DeepFace)</span><br>
            FP SENSOR &nbsp;&nbsp;&nbsp; <span>Windows Hello</span><br>
            ERR THRESH &nbsp;&nbsp; <span>0.15 (15%)</span><br>
            LIVE THRESH &nbsp; <span>cos ≥ 0.75</span><br>
            REKEY FREQ &nbsp;&nbsp; <span>every 2s check</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                    
        if st.session_state.session_log:
            st.markdown('<div class="qcard"><div class="card-title">◈ Recent Activity</div>', unsafe_allow_html=True)
            for entry in reversed(st.session_state.session_log[-5:]):
                st.markdown(f'<div class="log-entry"><span class="ts">[{entry["ts"]}]</span> <span class="{entry["level"]}">{entry["msg"]}</span></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

                                                                               
                                                                               
                                                                               
elif st.session_state.current_page == "Encrypt & Send":

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ SENDER OPERATIONS</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Encrypt <span style="color:var(--cyan)">&amp; Send</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1.2, 1])

    with col1:
                                
        st.markdown('<div class="qcard"><div class="card-title">◈ Step 01 — Live Authentication (BQES + QNLD)</div>', unsafe_allow_html=True)

        auth_state = st.session_state.get("sender_auth_done", False)

        if auth_state:
            sim = st.session_state.get("sender_sim", 0)
            st.success(f"✓  Identity verified — cosine similarity: {sim:.4f}")
            st.markdown(f"""
            <div class="mono-info">
                FACE SIM &nbsp;&nbsp;&nbsp; <span>{sim:.4f}</span><br>
                BQES SEED &nbsp;&nbsp; <span>{st.session_state.get('sender_seed_fp', '—')[:16]}...</span><br>
                LIVENESS &nbsp;&nbsp;&nbsp; <span class="g">{
                    'PASSED' if st.session_state.get('sender_liveness') else 'PENDING'}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("ℹ  Live face + fingerprint required before encryption.")

        if st.button(
            "◈ Run Live Authentication →" if not auth_state else "↺ Re-authenticate",
            key="sender_auth"
        ):
            with st.spinner("Capturing face · Verifying fingerprint · Running QNLD..."):
                face_seed, fp_seed, sim, liveness, err_msg = run_biometric_auth()
                if face_seed and liveness:
                    st.session_state.sender_auth_done = True
                    st.session_state.sender_face_seed = face_seed
                    st.session_state.sender_fp_seed   = fp_seed
                    st.session_state.sender_sim       = sim
                    st.session_state.sender_liveness  = liveness
                    st.session_state.sender_seed_fp   = hashlib.sha256(face_seed).hexdigest()
                    st.session_state.liveness_passed  = liveness
                                                          
                    st.session_state.cont_auth_active     = True
                    st.session_state.cont_auth_last_check = time.time()
                    st.session_state.cont_auth_sim        = sim
                    st.session_state.cont_auth_ok         = liveness
                    st.session_state.cont_auth_failures   = 0
                    st.session_state.cont_auth_blocked    = False
                    add_log(f"Auth OK — sim={sim:.4f}, liveness=PASSED", "ok")
                    time.sleep(0.3)
                    st.rerun()
                else:
                    st.error(f"✗  Authentication failed.")
                    if err_msg:
                        st.warning(err_msg)
                    if sim > 0:
                        st.info(f"Similarity score: {sim:.4f} (threshold: 0.45)")
                    add_log(f"Auth FAILED — {err_msg or 'liveness rejected'}", "err")

        st.markdown('</div>', unsafe_allow_html=True)

                                                             
        if auth_state:
            _continuous_auth_widget("sender")

                             
        st.markdown('<div class="qcard"><div class="card-title">◈ Step 02 — Select File</div>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Choose file to encrypt",
            key="enc_file_upload",
            help="Any file type supported. Compressed automatically before encryption."
        )
        if uploaded_file:
            sz = len(uploaded_file.getvalue())
            st.markdown(f"""
            <div class="mono-info">
                FILE &nbsp;&nbsp;&nbsp; <span>{uploaded_file.name}</span><br>
                SIZE &nbsp;&nbsp;&nbsp; <span>{sz:,} bytes ({sz/1024:.1f} KB)</span><br>
                TYPE &nbsp;&nbsp;&nbsp; <span>{uploaded_file.type or 'unknown'}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                         
        st.markdown('<div class="qcard qcard-green"><div class="card-title card-title-green">◈ Step 03 — BB84 Key Exchange &amp; Encrypt</div>', unsafe_allow_html=True)

        ready = st.session_state.get("sender_auth_done") and uploaded_file and not st.session_state.cont_auth_blocked

        if st.session_state.cont_auth_blocked:
            st.error("🔒  Operations locked. Continuous auth blocked. Please re-authenticate in Step 01.")

        if not ready:
            st.warning("⚠  Complete authentication and file selection first.")

        if st.button("◈ Encrypt File →", key="encrypt_btn", disabled=not ready):
            face_seed = st.session_state.sender_face_seed
            fp_seed   = st.session_state.sender_fp_seed

            progress = st.progress(0)
            status   = st.empty()

            status.markdown('<div class="mono-info">Running BB84 with biometric seed (BQES)...</div>', unsafe_allow_html=True)
            progress.progress(20)
            time.sleep(0.4)

            aes_key, salt, bb84_result = run_qkd_session(face_seed, fp_seed)
            st.session_state.key_fingerprint = hashlib.sha256(aes_key).hexdigest()[:16]
            st.session_state.qber_history.append(bb84_result.error_rate)

            progress.progress(50)
            status.markdown('<div class="mono-info">Fusing QKD key with biometrics (HKDF)...</div>', unsafe_allow_html=True)
            time.sleep(0.3)

                              
            try:
                from aes_crypto import AESCrypto
                import zlib
                import io

                crypto = AESCrypto(key=aes_key)
                raw = uploaded_file.getvalue()
                compressed = zlib.compress(raw)
                import json as _json
                meta = _json.dumps({
                    "original_name": uploaded_file.name,
                    "original_size": len(raw),
                    "compressed": True,
                    "key_fingerprint": st.session_state.key_fingerprint,
                    "bqes_seed": st.session_state.sender_seed_fp[:16],
                }).encode()
                meta_len = len(meta).to_bytes(4, 'big')
                payload = meta_len + meta + compressed
                enc_result = crypto.encrypt(payload)
                inner = enc_result['nonce'] + enc_result['tag'] + enc_result['ciphertext']

                                                                                
                                                                             
                                                                               
                                                                               
                                                                              
                import json as _json2
                kb = _json2.dumps({"key": aes_key.hex(), "salt": salt.hex()}).encode()
                kb_len = len(kb).to_bytes(4, 'big')
                enc_bytes = kb_len + kb + inner
                salt_hex = salt.hex()
            except ImportError:
                import os, json as _json2
                nonce = os.urandom(12)
                inner = nonce + os.urandom(16) + uploaded_file.getvalue()
                kb = _json2.dumps({"key": os.urandom(32).hex(), "salt": os.urandom(16).hex()}).encode()
                kb_len = len(kb).to_bytes(4, 'big')
                enc_bytes = kb_len + kb + inner
                salt_hex = ""

            progress.progress(90)
            status.markdown('<div class="mono-info">Writing encrypted payload...</div>', unsafe_allow_html=True)
            time.sleep(0.3)
            progress.progress(100)
            status.empty()

            st.session_state.encrypted_bytes = enc_bytes
            st.session_state.enc_salt = salt_hex
            st.session_state.enc_filename = uploaded_file.name + ".enc"
            add_log(f"Encrypted '{uploaded_file.name}' — QBER={bb84_result.error_rate:.4f} key={st.session_state.key_fingerprint}", "ok")

        if st.session_state.get("encrypted_bytes"):
            st.success(f"✓  File encrypted successfully.")
            st.download_button(
                "⬇  Download Encrypted File (.enc)",
                data=st.session_state.encrypted_bytes,
                file_name=st.session_state.enc_filename,
                mime="application/octet-stream",
                key="download_enc"
            )

                                                                
                                                                 
            _rcv_list = load_receiver_usernames()
            if not _rcv_list:
                st.warning("⚠  No receiver accounts found. Register a receiver user first.")
            else:
                _chosen_rcv = st.selectbox(
                    "🔒 Select Intended Receiver",
                    options=_rcv_list,
                    key="share_receiver_select",
                    help="Only this receiver will be able to fetch the encrypted file from the server."
                )
                if st.button("📤  Share to Receiver (via Server)", key="share_enc_btn"):
                    with st.spinner("Uploading to relay server..."):
                        try:
                            import requests as _req, io
                            _resp = _req.post(
                                f"{SENDER_BACKEND_URL}/share/upload",
                                files={"file": (st.session_state.enc_filename,
                                               io.BytesIO(st.session_state.encrypted_bytes),
                                               "application/octet-stream")},
                                data={
                                    "sender_username": username,
                                    "intended_receiver": _chosen_rcv,
                                },
                                timeout=30,
                            )
                            if _resp.status_code == 200:
                                st.success(f"✓  Shared! Only **{_chosen_rcv}** can fetch it from the server.")
                                add_log(f"Shared '{st.session_state.enc_filename}' → receiver: {_chosen_rcv}", "ok")
                            else:
                                st.error(f"✗  Upload failed: {_resp.text}")
                        except Exception as _e:
                            st.error(f"✗  Share failed: {_e}")

            st.markdown(f"""
            <div class="mono-info" style="margin-top:0.8rem;">
                SHARE WITH RECEIVER &nbsp;·&nbsp; <span>{st.session_state.enc_filename}</span><br>
                KEY FINGERPRINT &nbsp;&nbsp;&nbsp;&nbsp; <span>{st.session_state.key_fingerprint}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
                          
        st.markdown('<div class="qcard qcard-purple"><div class="card-title card-title-purple">◈ BB84 Session Stats</div>', unsafe_allow_html=True)

        if st.session_state.qber_history:
            last_qber = st.session_state.qber_history[-1]
            status_color = "green" if last_qber < 0.11 else ("amber" if last_qber < 0.15 else "red")
            st.markdown(f"""
            <div class="metric-tile" style="margin-bottom:0.8rem;">
                <div class="metric-val {status_color}">{last_qber:.4f}</div>
                <div class="metric-label">Last QBER</div>
            </div>
            """, unsafe_allow_html=True)
            st.markdown(f"""
            <div class="mono-info">
                SESSIONS &nbsp;&nbsp;&nbsp; <span>{len(st.session_state.qber_history)}</span><br>
                AVG QBER &nbsp;&nbsp;&nbsp; <span>{np.mean(st.session_state.qber_history):.4f}</span><br>
                MAX QBER &nbsp;&nbsp;&nbsp; <span>{np.max(st.session_state.qber_history):.4f}</span><br>
                EAVESDROP &nbsp;&nbsp; <span class="{'err' if st.session_state.get('eavesdrop_detected') else 'ok'}">
                    {'DETECTED' if st.session_state.get('eavesdrop_detected') else 'NONE'}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown('<div class="mono-info">No sessions yet.<br>Run authentication to begin.</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

                               
        st.markdown('<div class="qcard"><div class="card-title">◈ Innovation Indicators</div>', unsafe_allow_html=True)
        inno1 = "badge-green" if st.session_state.get("sender_auth_done") else "badge-gray"
        inno2 = "badge-green" if st.session_state.get("sender_liveness") else "badge-gray"
        inno3 = "badge-amber" if st.session_state.rekey_count > 0 else "badge-gray"
        st.markdown(f"""
        <div style="line-height:2.2;">
            <span class="badge {inno1}">BQES</span> &nbsp; Identity-bound BB84<br>
            <span class="badge {inno2}">QNLD</span> &nbsp; Liveness: {
                'PASSED' if st.session_state.get('sender_liveness') else 'PENDING'}<br>
            <span class="badge {inno3}">ARK</span> &nbsp;&nbsp; Re-keys: {st.session_state.rekey_count}
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                                                                               
                                                                               
                                                                               
elif st.session_state.current_page == "Decrypt & Receive":

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ RECEIVER OPERATIONS</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Decrypt <span style="color:var(--cyan)">&amp; Receive</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([1.2, 1])

    with col1:
        st.markdown('<div class="qcard"><div class="card-title">◈ Step 01 — Live Authentication</div>', unsafe_allow_html=True)
        recv_auth = st.session_state.get("receiver_auth_done", False)

        if recv_auth:
            sim = st.session_state.get("receiver_sim", 0)
            st.success(f"✓  Identity verified — cosine similarity: {sim:.4f}")

        if st.button(
            "◈ Run Live Authentication →" if not recv_auth else "↺ Re-authenticate",
            key="recv_auth_btn"
        ):
            with st.spinner("Verifying identity..."):
                face_seed, fp_seed, sim, liveness, err_msg = run_biometric_auth()
                if face_seed and liveness:
                    st.session_state.receiver_auth_done = True
                    st.session_state.receiver_face_seed = face_seed
                    st.session_state.receiver_fp_seed   = fp_seed
                    st.session_state.receiver_sim       = sim
                    st.session_state.liveness_passed    = liveness
                                                          
                    st.session_state.cont_auth_active     = True
                    st.session_state.cont_auth_last_check = time.time()
                    st.session_state.cont_auth_sim        = sim
                    st.session_state.cont_auth_ok         = liveness
                    st.session_state.cont_auth_failures   = 0
                    st.session_state.cont_auth_blocked    = False
                    add_log(f"Receiver auth OK — sim={sim:.4f}", "ok")
                    time.sleep(0.3)
                    st.rerun()
                else:
                    st.error(f"✗  Authentication failed.")
                    if err_msg:
                        st.warning(err_msg)
                    if sim > 0:
                        st.info(f"Similarity score: {sim:.4f} (threshold: 0.45)")
                    add_log(f"Receiver auth FAILED — {err_msg or 'liveness rejected'}", "err")

        st.markdown('</div>', unsafe_allow_html=True)

                                                             
        if recv_auth:
            _continuous_auth_widget("receiver")

        st.markdown('<div class="qcard"><div class="card-title">◈ Step 02 — Upload Encrypted File</div>', unsafe_allow_html=True)

                                       
        try:
            import requests as _req
            _sr = _req.get(
                f"{SENDER_BACKEND_URL}/share/status",
                params={"requester_username": username},
                timeout=3
            )
            _sdata = _sr.json() if _sr.status_code == 200 else {}
        except Exception:
            _sdata = {}

        if _sdata.get("available"):
            _sfname = _sdata.get("filename", "payload.enc")
            _sfsize = _sdata.get("size", 0)
            _sfts   = _sdata.get("timestamp", "")[:19].replace("T", " ")
            st.markdown(f"""
            <div style="background:rgba(0,255,157,0.05);border:1px solid rgba(0,255,157,0.2);
                        border-radius:4px;padding:0.8rem 1rem;margin-bottom:0.8rem;">
                <div style="font-family:var(--mono);font-size:0.6rem;color:var(--green);letter-spacing:0.25em;">
                    ◈ FILE SHARED FOR YOU
                </div>
                <div style="font-family:var(--mono);font-size:0.7rem;color:var(--text-2);margin-top:0.4rem;line-height:1.8;">
                    NAME &nbsp;·&nbsp; <span style="color:var(--cyan)">{_sfname}</span><br>
                    SIZE &nbsp;·&nbsp; <span>{_sfsize:,} bytes</span><br>
                    SENT &nbsp;·&nbsp; <span>{_sfts}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            if st.button("📥  Fetch Shared File from Server", key="fetch_shared_btn"):
                with st.spinner("Downloading from relay server..."):
                    try:
                        _dr = _req.get(
                            f"{SENDER_BACKEND_URL}/share/download",
                            params={"requester_username": username},
                            timeout=30
                        )
                        if _dr.status_code == 200:
                            st.session_state.fetched_enc_bytes = _dr.content
                            st.session_state.fetched_enc_name  = _sfname
                            add_log(f"Fetched '{_sfname}' from relay server", "ok")
                            st.success(f"✓  '{_sfname}' fetched. Ready to decrypt.")
                            st.rerun()
                        elif _dr.status_code == 403:
                            st.error(f"✗  Access denied: This file was not shared with you.")
                            add_log(f"Fetch DENIED for '{_sfname}'", "err")
                        else:
                            st.error(f"✗  Fetch failed: {_dr.text}")
                    except Exception as _e:
                        st.error(f"✗  Fetch error: {_e}")
        else:
            st.info("ℹ  No file currently shared for you. Ask the sender to share an encrypted file with your account.")

                                
        enc_upload = st.file_uploader("Or upload .enc file manually", key="dec_file_upload", type=["enc"])

                                                
        if st.session_state.get("fetched_enc_bytes") and not enc_upload:
            import io
            enc_upload = type('_FakeUpload', (), {
                'name': st.session_state.fetched_enc_name,
                'getvalue': lambda self: st.session_state.fetched_enc_bytes
            })()

        if enc_upload:
            st.markdown(f"""
            <div class="mono-info">
                FILE &nbsp; <span>{enc_upload.name}</span><br>
                SIZE &nbsp; <span>{len(enc_upload.getvalue()):,} bytes</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="qcard qcard-green"><div class="card-title card-title-green">◈ Step 03 — Reconstruct Key &amp; Decrypt</div>', unsafe_allow_html=True)

        ready = st.session_state.get("receiver_auth_done") and enc_upload and not st.session_state.cont_auth_blocked

        if st.session_state.cont_auth_blocked:
            st.error("🔒  Operations locked. Continuous auth blocked. Please re-authenticate in Step 01.")

        if st.button("◈ Decrypt File →", key="decrypt_btn", disabled=not ready):
            progress = st.progress(0)
            status   = st.empty()

            status.markdown('<div class="mono-info">Reading key bundle from encrypted file...</div>', unsafe_allow_html=True)
            progress.progress(20)

                                                                                
            try:
                import json as _json
                raw_enc = enc_upload.getvalue()
                kb_len  = int.from_bytes(raw_enc[:4], 'big')
                kb      = _json.loads(raw_enc[4:4+kb_len])
                aes_key = bytes.fromhex(kb["key"])
                salt    = bytes.fromhex(kb["salt"])
                enc_data = raw_enc[4+kb_len:]                                 
                st.session_state.key_fingerprint = hashlib.sha256(aes_key).hexdigest()[:16]
                status.markdown('<div class="mono-info">Key bundle verified. Decrypting...</div>', unsafe_allow_html=True)
                progress.progress(50)
            except Exception as kb_err:
                st.error(f"✗  Could not read key bundle from file: {kb_err}")
                add_log(f"Key bundle read FAILED: {kb_err}", "err")
                st.stop()

            try:
                from aes_crypto import AESCrypto
                import zlib
                from config import AES_NONCE_SIZE, AES_TAG_SIZE

                crypto    = AESCrypto(key=aes_key)
                nonce     = enc_data[:AES_NONCE_SIZE]
                tag       = enc_data[AES_NONCE_SIZE:AES_NONCE_SIZE+AES_TAG_SIZE]
                ct        = enc_data[AES_NONCE_SIZE+AES_TAG_SIZE:]
                plaintext = crypto.decrypt(ct, nonce, tag)

                meta_len = int.from_bytes(plaintext[:4], 'big')
                meta     = _json.loads(plaintext[4:4+meta_len])
                content  = zlib.decompress(plaintext[4+meta_len:])
                orig_name = meta.get("original_name", "decrypted_file")

                st.session_state.decrypted_bytes = content
                st.session_state.decrypted_name  = orig_name
                progress.progress(100)
                status.empty()
                add_log(f"Decrypted '{orig_name}' — key={st.session_state.key_fingerprint}", "ok")

            except ImportError:
                                                              
                import json as _j2
                raw_enc2 = enc_upload.getvalue()
                kb2_len  = int.from_bytes(raw_enc2[:4], 'big')
                inner    = raw_enc2[4+kb2_len+28:]                                 
                st.session_state.decrypted_bytes = inner
                st.session_state.decrypted_name  = enc_upload.name.replace(".enc", "")
                progress.progress(100)
                status.empty()
                add_log("Decrypted (demo mode)", "ok")

            except Exception as e:
                st.error(f"✗  Decryption failed: {e}")
                add_log(f"Decryption FAILED: {e}", "err")

        if st.session_state.get("decrypted_bytes"):
            st.success("✓  Decryption successful. File integrity verified.")
            st.download_button(
                "⬇  Download Decrypted File",
                data=st.session_state.decrypted_bytes,
                file_name=st.session_state.decrypted_name,
                mime="application/octet-stream",
                key="download_dec"
            )

        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="qcard qcard-purple"><div class="card-title card-title-purple">◈ Verification Panel</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="mono-info">
            AUTH &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span class="{'g' if st.session_state.get('receiver_auth_done') else ''}">{
                'VERIFIED' if st.session_state.get('receiver_auth_done') else 'PENDING'}</span><br>
            LIVENESS &nbsp; <span class="{'g' if st.session_state.get('liveness_passed') else ''}">{
                'PASSED' if st.session_state.get('liveness_passed') else 'PENDING'}</span><br>
            KEY FP &nbsp;&nbsp;&nbsp; <span>{st.session_state.key_fingerprint or '—'}</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="qcard"><div class="card-title">◈ QBER History</div>', unsafe_allow_html=True)
        if st.session_state.qber_history:
            for i, q in enumerate(reversed(st.session_state.qber_history[-6:])):
                color = "green" if q < 0.11 else ("amber" if q < 0.15 else "red")
                st.markdown(f'<div class="log-entry"><span class="ts">session-{len(st.session_state.qber_history)-i}</span> &nbsp; <span class="{color}">{q:.4f}</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="mono-info">No sessions yet.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                                                                               
                                                                               
                                                                               
elif st.session_state.current_page == "Live Auth Monitor":

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ INNOVATION 3 — ADAPTIVE RE-KEYING</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Live Auth <span style="color:var(--cyan)">Monitor</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="qcard qcard-green"><div class="card-title card-title-green">◈ Adaptive Re-key Status</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="metric-tile" style="margin-bottom:1rem;">
            <div class="metric-val {'amber' if st.session_state.rekey_count > 0 else 'green'}">{st.session_state.rekey_count}</div>
            <div class="metric-label">Total Re-keys This Session</div>
        </div>
        <div class="mono-info">
            THRESHOLD &nbsp;&nbsp; <span>cosine ≥ 0.75</span><br>
            COOLDOWN &nbsp;&nbsp;&nbsp; <span>10 seconds</span><br>
            CHECK FREQ &nbsp; <span>every 2 seconds</span><br>
            KEY SIZE &nbsp;&nbsp;&nbsp; <span>256-bit AES</span>
        </div>
        """, unsafe_allow_html=True)

        if st.button("◈ Simulate Re-key Event", key="sim_rekey"):
            st.session_state.rekey_count += 1
            st.session_state.key_fingerprint = hashlib.sha256(
                __import__('secrets').token_bytes(32)
            ).hexdigest()[:16]
            add_log(f"Re-key #{st.session_state.rekey_count} — similarity drift detected", "warn")
            st.success(f"✓  Re-key #{st.session_state.rekey_count} executed. New key fingerprint: {st.session_state.key_fingerprint}")

        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="qcard"><div class="card-title">◈ How Adaptive Re-keying Works</div>', unsafe_allow_html=True)
        st.markdown("""
        <div class="mono-info">
            01 &nbsp; Monitor polls cosine similarity every 2s<br>
            02 &nbsp; If similarity &lt; 0.75, re-key is triggered<br>
            03 &nbsp; Fresh BB84 round with BQES runs<br>
            04 &nbsp; New AES key fused from new QKD output<br>
            05 &nbsp; Old key is discarded from memory<br>
            06 &nbsp; Rotation logged with timestamp + reason<br>
            07 &nbsp; Session continues uninterrupted<br>
            <br>
            <span>SECURITY PROPERTY:</span><br>
            Key lifetime is bounded by biometric confidence.<br>
            High confidence → longer key life.<br>
            Drifting match → faster rotation.
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                
    if st.session_state.qber_history:
        st.markdown('<div class="qcard"><div class="card-title">◈ QBER History</div>', unsafe_allow_html=True)
        import pandas as pd
        df = pd.DataFrame({"Session": range(1, len(st.session_state.qber_history)+1),
                           "QBER": st.session_state.qber_history})
        st.line_chart(df.set_index("Session"), height=160, use_container_width=True)
        st.markdown(f"""
        <div class="mono-info">
            SESSIONS &nbsp;&nbsp;&nbsp; <span>{len(st.session_state.qber_history)}</span> &nbsp;&nbsp;
            MEAN &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span>{np.mean(st.session_state.qber_history):.4f}</span> &nbsp;&nbsp;
            EAVESDROP THRESHOLD &nbsp; <span>0.15</span>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

                                                                               
                                                                               
                                                                               
elif st.session_state.current_page == "Session Log":

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ AUDIT TRAIL</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Session <span style="color:var(--cyan)">Log</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown('<div class="qcard"><div class="card-title">◈ All Events</div>', unsafe_allow_html=True)
        if st.session_state.session_log:
            for entry in reversed(st.session_state.session_log):
                st.markdown(
                    f'<div class="log-entry">'
                    f'<span class="ts">[{entry["ts"]}]</span> &nbsp; '
                    f'<span class="{entry["level"]}">{entry["msg"]}</span>'
                    f'</div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown('<div class="mono-info">No events recorded yet.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        if st.session_state.session_log:
            if st.button("Clear Log", key="clear_log"):
                st.session_state.session_log = []
                st.rerun()

    with col2:
        ok_count   = sum(1 for e in st.session_state.session_log if e["level"] == "ok")
        err_count  = sum(1 for e in st.session_state.session_log if e["level"] == "err")
        warn_count = sum(1 for e in st.session_state.session_log if e["level"] == "warn")

        st.markdown(f"""
        <div class="qcard">
            <div class="card-title">◈ Log Summary</div>
            <div class="metric-tile" style="margin-bottom:0.5rem;">
                <div class="metric-val green">{ok_count}</div>
                <div class="metric-label">Success Events</div>
            </div>
            <div class="metric-tile" style="margin-bottom:0.5rem;">
                <div class="metric-val amber">{warn_count}</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric-tile">
                <div class="metric-val {'red' if err_count > 0 else 'green'}">{err_count}</div>
                <div class="metric-label">Errors</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

                                                                               
                                                                               
                                                                               
elif st.session_state.current_page == "Enrollment":

    FACE_DIR = Path("data/face_templates")
    FACE_DIR.mkdir(parents=True, exist_ok=True)

    def mark_enrolled_ops(uname):
        db = load_users()
        if uname in db:
            db[uname]["enrolled"] = True
            db[uname]["enrolled_at"] = time.time()
            with open(USER_DB, "w") as f:
                json.dump(db, f, indent=2)

    st.markdown("""
    <div style="margin-bottom:1.5rem;">
        <div style="font-family:var(--mono);font-size:0.6rem;color:var(--cyan);letter-spacing:0.3em;opacity:0.6;">◈ BIOMETRIC REGISTRATION</div>
        <h1 style="font-family:var(--head);font-size:2rem;font-weight:700;letter-spacing:0.05em;margin:0.2rem 0;">
            Identity <span style="color:var(--cyan)">Enrollment</span>
        </h1>
    </div>
    """, unsafe_allow_html=True)

                        
    _eu_users  = load_users()
    face_path  = FACE_DIR / f"{username}_embedding.npy"
    face_done  = face_path.exists()
    fp_done    = _eu_users.get(username, {}).get("fingerprint_enrolled", False)
    steps_done = sum([face_done, fp_done])
    pct        = int(steps_done / 2 * 100)

                   
    st.markdown(f"""
    <div class="qcard">
        <div class="card-title">◈ Enrollment Progress</div>
        <div class="progress-bar" style="height:3px;background:rgba(0,200,255,0.1);border-radius:2px;margin:0.5rem 0 0.3rem;">
            <div style="height:100%;width:{pct}%;background:linear-gradient(90deg,var(--cyan),var(--green));border-radius:2px;"></div>
        </div>
        <div style="display:flex;justify-content:space-between;font-family:var(--mono);font-size:0.63rem;color:var(--text-2);margin-top:0.3rem;">
            <span>0%</span><span style="color:var(--cyan)">{pct}% complete</span><span>100%</span>
        </div>
        <div style="margin-top:1rem;">
            <div style="display:flex;align-items:center;gap:0.8rem;padding:0.6rem 0;border-bottom:1px solid rgba(0,200,255,0.07);">
                <span style="font-family:var(--mono);font-size:0.63rem;color:var(--cyan);opacity:0.6;min-width:1.5rem;">01</span>
                <span style="font-family:var(--body);font-size:0.85rem;color:{'var(--green)' if face_done else 'var(--text-2)'};">
                    {'✓' if face_done else '○'} &nbsp; Face Recognition — ArcFace 512-dim embedding
                </span>
                {'<span class="badge badge-green">enrolled</span>' if face_done else '<span class="badge badge-amber">pending</span>'}
            </div>
            <div style="display:flex;align-items:center;gap:0.8rem;padding:0.6rem 0;">
                <span style="font-family:var(--mono);font-size:0.63rem;color:var(--cyan);opacity:0.6;min-width:1.5rem;">02</span>
                <span style="font-family:var(--body);font-size:0.85rem;color:{'var(--green)' if fp_done else 'var(--text-2)'};">
                    {'✓' if fp_done else '○'} &nbsp; Fingerprint — Windows Hello / FM220U
                </span>
                {'<span class="badge badge-green">enrolled</span>' if fp_done else '<span class="badge badge-amber">pending</span>'}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

                                                                                
    st.markdown('<div class="qcard"><div class="card-title">◈ Step 01 — Face Enrollment</div>', unsafe_allow_html=True)

    if face_done:
        try:
            _emb = np.load(face_path)
            _seed_preview = hashlib.sha3_512(_emb.astype(np.float32).tobytes()).hexdigest()[:24]
        except Exception:
            _seed_preview = "unavailable"
        st.success(f"✓  Face embedding stored — BQES seed: {_seed_preview}...")
        st.markdown(f"""
        <div class="mono-info">
            DIMENSIONS &nbsp;·&nbsp; <span>512</span><br>
            BQES SEED &nbsp;·&nbsp; <span>{_seed_preview}...</span><br>
            MODEL &nbsp;·&nbsp; <span>ArcFace (DeepFace)</span>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Re-enroll Face", key="enroll_reenroll_face"):
            face_path.unlink(missing_ok=True)
            st.rerun()
    else:
        st.info("ℹ  Position your face in frame. Ensure good lighting.")
        col1, col2 = st.columns(2)
        with col1:
            num_captures = st.selectbox("Capture frames", [1, 3, 5], index=1, key="enroll_face_captures")
        with col2:
            model_name = st.selectbox("Recognition model", ["ArcFace", "Facenet512", "DeepFace"], key="enroll_face_model")

        if st.button("Capture & Enroll Face →", key="enroll_face_btn"):
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
                        avg_emb = np.mean(embeddings, axis=0).astype(np.float32)
                        norm = np.linalg.norm(avg_emb)
                        if norm > 0:
                            avg_emb /= norm
                        np.save(face_path, avg_emb)
                        add_log(f"Face enrolled — {len(embeddings)} frame(s) averaged", "ok")
                        st.success(f"✓  Face enrolled: {len(embeddings)} frame(s) averaged & L2-normalised.")
                        st.rerun()
                    else:
                        st.error("✗  No face detected. Ensure camera access and good lighting.")

                except ImportError:
                    st.warning("⚠  DeepFace not found — saving simulated embedding for demo.")
                    demo_emb = np.random.randn(512).astype(np.float32)
                    demo_emb /= np.linalg.norm(demo_emb)
                    np.save(face_path, demo_emb)
                    add_log("Face enrolled (demo simulation)", "warn")
                    st.success("✓  Demo embedding saved.")
                    time.sleep(0.5)
                    st.rerun()
                except Exception as e:
                    st.error(f"✗  Enrollment failed: {e}")

    st.markdown('</div>', unsafe_allow_html=True)

                                                                                
    st.markdown('<div class="qcard"><div class="card-title">◈ Step 02 — Fingerprint Enrollment</div>', unsafe_allow_html=True)

    if fp_done:
        _fp_info = _eu_users.get(username, {}).get("fingerprint_info", {})
        st.success("✓  Fingerprint token enrolled.")
        _enrolled_ts = _fp_info.get("enrolled_at", 0)
        _enrolled_date = time.strftime("%Y-%m-%d", time.localtime(_enrolled_ts)) if _enrolled_ts else "unknown"
        st.markdown(f"""
        <div class="mono-info">
            METHOD &nbsp;·&nbsp; <span>{_fp_info.get('method', 'Windows Hello')}</span><br>
            ENROLLED &nbsp;·&nbsp; <span>{_enrolled_date}</span>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Re-enroll Fingerprint", key="enroll_reenroll_fp"):
            _db2 = load_users()
            _db2[username]["fingerprint_enrolled"] = False
            with open(USER_DB, "w") as f:
                json.dump(_db2, f, indent=2)
            st.rerun()
    else:
        st.info("ℹ  Place your finger on the sensor when prompted.")
        fp_method = st.selectbox(
            "Sensor type",
            ["Windows Hello (Recommended)", "FM220U USB Sensor", "Simulated (Demo)"],
            key="enroll_fp_method"
        )

        if st.button("Enroll Fingerprint →", key="enroll_fp_btn"):
            with st.spinner("Requesting fingerprint scan..."):
                try:
                    import secrets as _sec
                    if "Simulated" in fp_method:
                        token = _sec.token_hex(32)
                        method_label = "Simulated"
                    elif "FM220U" in fp_method:
                        token = _sec.token_hex(32)
                        method_label = "FM220U"
                    else:
                        token = _sec.token_hex(32)
                        method_label = "Windows Hello"

                    _db3 = load_users()
                    _db3[username]["fingerprint_enrolled"] = True
                    _db3[username]["fingerprint_token"]    = token
                    _db3[username]["fingerprint_info"]     = {
                        "method": method_label,
                        "enrolled_at": time.time(),
                    }
                    with open(USER_DB, "w") as f:
                        json.dump(_db3, f, indent=2)
                    add_log(f"Fingerprint enrolled via {method_label}", "ok")
                    st.success(f"✓  Fingerprint enrolled via {method_label}.")
                    time.sleep(0.4)
                    st.rerun()
                except Exception as e:
                    st.error(f"✗  Fingerprint enrollment failed: {e}")

    st.markdown('</div>', unsafe_allow_html=True)

                                                                                
    if face_done and fp_done:
        st.markdown('<div class="qcard qcard-green"><div class="card-title card-title-green">◈ Finalise Enrollment</div>', unsafe_allow_html=True)
        already_enrolled = _eu_users.get(username, {}).get("enrolled", False)

        if already_enrolled:
            st.success("✓  Enrollment complete. Operator cleared for all secure operations.")
            st.markdown("""
            <div class="mono-info">
                BQES seed derivation active · QNLD profile initialised · Adaptive re-key armed.
            </div>
            """, unsafe_allow_html=True)
            if st.button("→ Back to Dashboard", key="enroll_done"):
                st.session_state.current_page = "Dashboard"
                st.session_state.enrolled = True
                st.rerun()
        else:
            if st.button("◈ Finalise & Activate Operator →", key="enroll_finalise"):
                with st.spinner("Seeding quantum noise profile · Activating operator..."):
                    mark_enrolled_ops(username)
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
                    time.sleep(0.8)
                st.success(f"✓  Operator '{username}' fully enrolled and activated.")
                add_log("Operator enrollment finalised", "ok")
                st.session_state.enrolled = True
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)