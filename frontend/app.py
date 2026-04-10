"""
QSec — Unified Gateway  (Login + Enrollment)
Port 8501 · Single-app design — no second port needed.

Navigation (via st.tabs after login):
  Tab 0 — Sign In / Register
  Tab 1 — Biometric Enrollment  (shown only when authenticated)
"""

import streamlit as st
import hashlib
import json
import os
import time
import numpy as np
from pathlib import Path

                                                                                
st.set_page_config(
    page_title="QSec — Quantum Secure Gateway",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

                                                                               
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Exo+2:wght@200;300;400;600&display=swap');

:root {
    --bg-deep:    #03070f;
    --bg-card:    #080f1e;
    --bg-glass:   rgba(10, 20, 45, 0.85);
    --border:     rgba(0, 200, 255, 0.18);
    --border-hot: rgba(0, 200, 255, 0.55);
    --cyan:       #00c8ff;
    --cyan-dim:   rgba(0, 200, 255, 0.10);
    --green:      #00ff9d;
    --green-dim:  rgba(0, 255, 157, 0.09);
    --red:        #ff3c6e;
    --amber:      #ffb400;
    --text-1:     #e8f4ff;
    --text-2:     #7ba8c4;
    --text-3:     #3d6278;
    --mono:       'Share Tech Mono', monospace;
    --head:       'Rajdhani', sans-serif;
    --body:       'Exo 2', sans-serif;
}

html, body, [class*="css"] {
    font-family: var(--body);
    background-color: var(--bg-deep) !important;
    color: var(--text-1);
}
.stApp {
    background: var(--bg-deep) !important;
    background-image:
        radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,200,255,0.07) 0%, transparent 60%),
        linear-gradient(180deg, rgba(0,200,255,0.03) 0%, transparent 40%) !important;
}
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 1.5rem !important; max-width: 900px !important; margin: 0 auto; }
/* Dashboard extras */
[data-testid="stSidebar"]{background:#060d1a!important;border-right:1px solid rgba(0,200,255,0.15)!important;}
.qcard-green::before{background:linear-gradient(90deg,transparent,var(--green),transparent);}
.qcard-purple::before{background:linear-gradient(90deg,transparent,#b48aff,transparent);}
.card-title-green{color:var(--green)!important;}
.card-title-purple{color:#b48aff!important;}
.badge-red{background:rgba(255,60,110,0.08);color:var(--red);border:1px solid rgba(255,60,110,0.25);}
.metric-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0.7rem;margin-bottom:1rem;}
.metric-tile{background:rgba(0,200,255,0.04);border:1px solid var(--border);border-radius:3px;padding:0.9rem;text-align:center;}
.metric-val{font-family:var(--mono);font-size:1.4rem;font-weight:500;color:var(--cyan);line-height:1;}
.metric-val.green{color:var(--green);} .metric-val.amber{color:var(--amber);} .metric-val.red{color:var(--red);}
.metric-label{font-family:var(--mono);font-size:0.58rem;color:var(--text-3);letter-spacing:0.15em;text-transform:uppercase;margin-top:0.3rem;}
.log-entry{font-family:var(--mono);font-size:0.7rem;color:var(--text-2);padding:0.35rem 0;border-bottom:1px solid rgba(0,200,255,0.06);}
.log-entry .ts{color:var(--text-3);} .log-entry .ok{color:var(--green);} .log-entry .warn{color:var(--amber);} .log-entry .err{color:var(--red);} .log-entry .info{color:var(--cyan);}

/* ── Hero ── */
.qsec-hero {
    text-align: center;
    padding: 2.5rem 0 1.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
}
.qsec-logo {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--cyan);
    letter-spacing: 0.25em;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
    opacity: 0.7;
}
.qsec-title {
    font-family: var(--head);
    font-size: 2.6rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    color: var(--text-1);
    line-height: 1;
    margin: 0;
}
.qsec-title span { color: var(--cyan); }
.qsec-sub {
    font-family: var(--body);
    font-size: 0.8rem;
    font-weight: 300;
    color: var(--text-2);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-top: 0.5rem;
}

/* ── Card ── */
.qcard {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 1.8rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
}
.qcard::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    opacity: 0.5;
}
.card-title {
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    color: var(--cyan);
    text-transform: uppercase;
    margin-bottom: 1.2rem;
    opacity: 0.75;
}

/* ── Inputs ── */
.stTextInput > div > div > input,
.stSelectbox > div > div > div {
    background: rgba(0, 200, 255, 0.04) !important;
    border: 1px solid var(--border) !important;
    border-radius: 3px !important;
    color: var(--text-1) !important;
    font-family: var(--mono) !important;
    font-size: 0.9rem !important;
    padding: 0.6rem 0.9rem !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--border-hot) !important;
    box-shadow: 0 0 0 2px var(--cyan-dim) !important;
}
.stTextInput label, .stSelectbox label {
    font-family: var(--mono) !important;
    font-size: 0.68rem !important;
    letter-spacing: 0.2em !important;
    color: var(--text-2) !important;
    text-transform: uppercase !important;
}

/* ── Buttons ── */
.stButton > button {
    width: 100%;
    background: transparent !important;
    border: 1px solid var(--border-hot) !important;
    color: var(--cyan) !important;
    font-family: var(--mono) !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.25em !important;
    text-transform: uppercase !important;
    padding: 0.7rem 1rem !important;
    border-radius: 3px !important;
    transition: all 0.2s !important;
    cursor: pointer;
}
.stButton > button:hover {
    background: var(--cyan-dim) !important;
    border-color: var(--cyan) !important;
    box-shadow: 0 0 18px rgba(0, 200, 255, 0.15) !important;
}
.btn-primary > button {
    background: linear-gradient(135deg, rgba(0,200,255,0.15), rgba(0,200,255,0.05)) !important;
    border-color: var(--cyan) !important;
}

/* ── Alerts ── */
.stSuccess > div {
    background: var(--green-dim) !important;
    border-left: 3px solid var(--green) !important;
    border-radius: 3px !important;
    color: var(--green) !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
}
.stError > div {
    background: rgba(255,60,110,0.08) !important;
    border-left: 3px solid var(--red) !important;
    border-radius: 3px !important;
    color: var(--red) !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
}
.stWarning > div {
    background: rgba(255,180,0,0.07) !important;
    border-left: 3px solid var(--amber) !important;
    border-radius: 3px !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
}
.stInfo > div {
    background: var(--cyan-dim) !important;
    border-left: 3px solid var(--cyan) !important;
    border-radius: 3px !important;
    color: var(--text-1) !important;
    font-family: var(--mono) !important;
    font-size: 0.8rem !important;
}

/* ── Badges ── */
.badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 0.63rem;
    letter-spacing: 0.18em;
    padding: 0.22rem 0.7rem;
    border-radius: 2px;
    text-transform: uppercase;
    margin: 0.15rem 0.2rem;
}
.badge-green { background: var(--green-dim); color: var(--green); border: 1px solid rgba(0,255,157,0.3); }
.badge-cyan  { background: var(--cyan-dim);  color: var(--cyan);  border: 1px solid rgba(0,200,255,0.3); }
.badge-gray  { background: rgba(255,255,255,0.04); color: var(--text-2); border: 1px solid var(--border); }
.badge-amber { background: rgba(255,180,0,0.08); color: var(--amber); border: 1px solid rgba(255,180,0,0.3); }

/* ── Enrollment specific ── */
.inno-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.8rem 0; }
.step-row { display:flex; align-items:center; gap:0.8rem; padding:0.7rem 0; border-bottom:1px solid rgba(0,200,255,0.07); }
.step-num { font-family:var(--mono); font-size:0.65rem; color:var(--cyan); opacity:0.6; min-width:1.5rem; }
.step-text { font-family:var(--body); font-size:0.85rem; color:var(--text-2); }
.step-done { color: var(--green) !important; }
.progress-bar { height:3px; background:rgba(0,200,255,0.1); border-radius:2px; margin:0.8rem 0 0.3rem; }
.progress-fill { height:100%; background:linear-gradient(90deg,var(--cyan),var(--green)); border-radius:2px; transition:width 0.5s ease; }
.mono-info { font-family:var(--mono); font-size:0.72rem; color:var(--text-2); line-height:1.9; }
.mono-info span { color: var(--cyan); }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: transparent !important;
    border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    font-family: var(--mono) !important;
    font-size: 0.68rem !important;
    letter-spacing: 0.2em !important;
    color: var(--text-2) !important;
    text-transform: uppercase !important;
    background: transparent !important;
    border: none !important;
    padding: 0.6rem 1.2rem !important;
}
.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
    border-bottom: 2px solid var(--cyan) !important;
}

/* ── Misc ── */
.qdivider { border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }
.qfooter {
    text-align: center;
    font-family: var(--mono);
    font-size: 0.6rem;
    color: var(--text-3);
    letter-spacing: 0.2em;
    padding: 2rem 0 1rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
}
.stSpinner > div { border-top-color: var(--cyan) !important; }
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
""", unsafe_allow_html=True)

                                                                                
USER_DB  = Path("data/users.json")
FACE_DIR = Path("data/face_templates")
USER_DB.parent.mkdir(parents=True, exist_ok=True)
FACE_DIR.mkdir(parents=True, exist_ok=True)

                                                                                
def load_users() -> dict:
    if USER_DB.exists():
        with open(USER_DB) as f:
            return json.load(f)
    return {}

def save_users(users: dict) -> None:
    with open(USER_DB, "w") as f:
        json.dump(users, f, indent=2)

def hash_password(pwd: str) -> str:
    return hashlib.sha256(pwd.encode()).hexdigest()

def authenticate(username: str, password: str) -> bool:
    users = load_users()
    if username in users:
        return users[username]["password"] == hash_password(password)
    return False

def register_user(username: str, password: str, role: str) -> bool:
    users = load_users()
    if username in users:
        return False
    users[username] = {
        "password": hash_password(password),
        "role": role,
        "enrolled": False,
        "created_at": time.time(),
    }
    save_users(users)
    return True

def is_enrolled(username: str) -> bool:
    return load_users().get(username, {}).get("enrolled", False)

def mark_enrolled(uname: str) -> None:
    users = load_users()
    if uname in users:
        users[uname]["enrolled"] = True
        users[uname]["enrolled_at"] = time.time()
        save_users(users)

                                                                                
for key, val in {
    "authenticated": False,
    "username": None,
    "role": None,
    "enrolled": False,
    "current_page": "__login__",                              
    "session_log": [],
    "rekey_count": 0,
    "qber_history": [],
    "key_fingerprint": None,
    "liveness_passed": None,
    "cont_auth_active": False,
    "cont_auth_last_check": 0.0,
    "cont_auth_sim": None,
    "cont_auth_ok": None,
    "cont_auth_failures": 0,
    "cont_auth_blocked": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = val

                                                                                
def ts(): return time.strftime("%H:%M:%S")
def add_log(msg, level="info"):
    st.session_state.session_log.append({"ts": ts(), "msg": msg, "level": level})

                                                                                
if st.session_state.current_page == "__login__":
    st.markdown("""
    <div class="qsec-hero">
        <div class="qsec-logo">◈ Quantum Secure Communications ◈</div>
        <h1 class="qsec-title">Q<span>SEC</span></h1>
        <div class="qsec-sub">BB84 · AES-256-GCM · Multimodal Biometrics</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div class="inno-row">
        <span class="badge badge-cyan">BQES · Biometric Entropy Seeding</span>
        <span class="badge badge-green">QNLD · Quantum Noise Liveness</span>
        <span class="badge badge-cyan">Adaptive Re-keying</span>
    </div>
    """, unsafe_allow_html=True)

                                                                                
              
                                                                                
if st.session_state.current_page == "__login__":
    tab_login, tab_register = st.tabs(["  Sign In  ", "  Register  "])

    with tab_login:
        st.markdown('<div class="qcard"><div class="card-title">◈ Identity Verification</div>', unsafe_allow_html=True)
        username = st.text_input("Username", key="login_user", placeholder="operator_id")
        password = st.text_input("Password", type="password", key="login_pass", placeholder="••••••••••••")
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('<div class="btn-primary">', unsafe_allow_html=True)
        if st.button("Authenticate →", key="login_btn"):
            if not username or not password:
                st.error("✗  All fields required.")
            elif authenticate(username, password):
                users = load_users()
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = users[username].get("role", "user")
                st.session_state.enrolled = is_enrolled(username)
                st.session_state.current_page = "Dashboard"
                with st.spinner("Initialising secure session..."):
                    time.sleep(0.5)
                st.rerun()
            else:
                st.error("✗  Invalid credentials. Access denied.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_register:
        st.markdown('<div class="qcard"><div class="card-title">◈ New Operator Registration</div>', unsafe_allow_html=True)
        new_user = st.text_input("Choose Username", key="reg_user", placeholder="operator_id")
        new_pass = st.text_input("Choose Password", type="password", key="reg_pass", placeholder="min. 8 characters")
        confirm  = st.text_input("Confirm Password", type="password", key="reg_conf", placeholder="repeat password")
        role     = st.selectbox("Operator Role", ["sender", "receiver"], key="reg_role")
        st.markdown('</div>', unsafe_allow_html=True)
        if st.button("Register Operator →", key="reg_btn"):
            if not all([new_user, new_pass, confirm]):
                st.error("✗  All fields required.")
            elif len(new_pass) < 8:
                st.error("✗  Password must be at least 8 characters.")
            elif new_pass != confirm:
                st.error("✗  Passwords do not match.")
            elif register_user(new_user, new_pass, role):
                st.success(f"✓  Operator '{new_user}' registered as {role}. Sign in to continue.")
            else:
                st.error(f"✗  Username '{new_user}' already exists.")

                                                                                
                                                           
                                                                                
elif st.session_state.authenticated:
                                                                              
                                                                             
                                                                           
                                                                               
                                                                      
    _dashboard = Path(__file__).parent / "streamlit_app.py"
    exec(compile(_dashboard.read_text(encoding="utf-8"), str(_dashboard), "exec"),
         {**globals(), "__file__": str(_dashboard)})

                                                                                
if st.session_state.current_page == "__login__":
    st.markdown("""
<div class="qfooter">
    QSEC MULTIMODAL SECURE COMM · BB84 + AES-256-GCM · BQES · QNLD · ADAPTIVE RE-KEYING<br>
    FOR AUTHORISED OPERATORS ONLY · ALL SESSIONS MONITORED AND LOGGED
</div>
""", unsafe_allow_html=True)

