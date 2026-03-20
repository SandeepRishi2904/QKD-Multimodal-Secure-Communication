# """
# QKD Multimodal Secure Communication System - Login Page

# Flow:
#   1. User selects role (Sender / Receiver)
#   2. Email + Password form appears for that role
#   3. Both must match the credentials defined in CREDENTIALS below
#   4. Correct → redirect to the respective Streamlit app
#   5. Wrong  → error message, max 5 attempts then lockout

# To change credentials, edit the CREDENTIALS dict below.

# Run: streamlit run login_app.py --server.port 8500
# """
# import requests
# from datetime import datetime
# import streamlit as st

# st.set_page_config(
#     page_title="QKD Secure Login",
#     page_icon="🔐",
#     layout="centered",
#     initial_sidebar_state="collapsed"
# )

# BACKEND_URL = "http://localhost:8000"

# # ── Credentials — edit here to change email / password ────────────────────────
# # Each role has its own independent email + password pair.
# CREDENTIALS = {
#     "sender": {
#         "email":    "rishikesh95430@gmail.com",
#         "password": "sender123",
#     },
#     "receiver": {
#         "email":    "jbsandeeprishi@gmail.com",
#         "password": "receiver123",
#     },
# }

# REDIRECT_URLS = {
#     "sender":   "http://localhost:8502",
#     "receiver": "http://localhost:8502",
# }
# ROLE_ICONS = {"sender": "📤", "receiver": "📥"}
# ROLE_GRADS = {
#     "sender":   ("135deg, #667eea 0%, #764ba2 100%", "rgba(102,126,234,0.3)"),
#     "receiver": ("135deg, #11998e 0%, #38ef7d 100%", "rgba(17,153,142,0.3)"),
# }

# # ── CSS ────────────────────────────────────────────────────────────────────────
# st.markdown("""
# <style>
#     #MainMenu { visibility: hidden; }
#     footer     { visibility: hidden; }
#     header     { visibility: hidden; }

#     .stApp {
#         background: linear-gradient(135deg, #0f0c29 0%, #1a1a4e 50%, #24243e 100%);
#         min-height: 100vh;
#     }

#     /* ── Typography ── */
#     .login-title {
#         font-size: 2rem; font-weight: 800; text-align: center;
#         color: #ffffff; letter-spacing: 0.5px; margin-bottom: 0.2rem;
#     }
#     .login-subtitle {
#         text-align: center; color: rgba(255,255,255,0.75);
#         font-size: 0.9rem; margin-bottom: 0.5rem;
#     }

#     /* ── Role cards ── */
#     .role-card {
#         border-radius: 1rem; padding: 1.2rem 1rem;
#         margin-bottom: 0.5rem; text-align: center;
#     }
#     .pw-banner {
#         border-radius: 0.85rem; padding: 0.9rem 1.2rem;
#         text-align: center; margin-bottom: 1rem;
#     }

#     /* ── Streamlit overrides ── */
#     .stButton > button {
#         border-radius: 0.75rem !important; font-weight: 700 !important;
#         height: 3rem !important; font-size: 0.95rem !important; width: 100% !important;
#     }
#     .stTextInput > div > div > input {
#         background: rgba(255,255,255,0.07) !important;
#         border: 1px solid rgba(255,255,255,0.18) !important;
#         border-radius: 0.6rem !important; color: #ffffff !important;
#         font-size: 0.95rem !important; padding: 0.65rem 0.9rem !important;
#     }
#     .stTextInput > div > div > input:focus {
#         border-color: #667eea !important;
#         box-shadow: 0 0 0 2px rgba(102,126,234,0.25) !important;
#     }
#     .stTextInput label {
#         color: rgba(255,255,255,0.55) !important;
#         font-size: 0.82rem !important;
#         font-weight: 600 !important;
#         margin-bottom: 0.2rem !important;
#     }

#     /* ── Status pills ── */
#     .status-online {
#         display:inline-block; background:rgba(56,239,125,0.15); color:#38ef7d;
#         border:1px solid rgba(56,239,125,0.3); border-radius:2rem;
#         padding:0.2rem 0.8rem; font-size:0.75rem; font-weight:600;
#     }
#     .status-offline {
#         display:inline-block; background:rgba(255,82,82,0.15); color:#ff5252;
#         border:1px solid rgba(255,82,82,0.3); border-radius:2rem;
#         padding:0.2rem 0.8rem; font-size:0.75rem; font-weight:600;
#     }
#     .warn-badge {
#         display:inline-block; background:rgba(255,193,7,0.15); color:#ffc107;
#         border:1px solid rgba(255,193,7,0.3); border-radius:2rem;
#         padding:0.1rem 0.55rem; font-size:0.68rem; font-weight:600;
#         margin-left:0.3rem; vertical-align:middle;
#     }

#     /* ── Bottom metric row ── */
#     .metric-row { display:flex; gap:0.5rem; margin-top:1.1rem; }
#     .metric-box {
#         flex:1; background:rgba(255,255,255,0.05); border-radius:0.6rem;
#         padding:0.55rem; text-align:center;
#     }
#     .metric-label { color: rgba(255,255,255,0.65); font-size: 0.68rem; text-transform:uppercase; letter-spacing:0.4px; }
#     .metric-value { color:#fff; font-size:0.9rem; font-weight:700; margin-top:0.15rem; }

#     /* ── Info / port strip ── */
#     .info-strip {
#         background:rgba(102,126,234,0.1); border-left:3px solid #667eea;
#         border-radius:0 0.5rem 0.5rem 0; padding:0.6rem 0.85rem;
#         color:rgba(255,255,255,0.8); font-size:0.82rem; margin-top:1.25rem;
#     }

#     /* ── Credential hint box ── */
#     .hint-box {
#         background: rgba(255,255,255,0.06);
#         border: 1px dashed rgba(255,255,255,0.2);
#         border-radius: 0.6rem;
#         padding: 0.6rem 0.85rem;
#         margin-top: 0.75rem;
#         font-size: 0.8rem;
#         color: rgba(255,255,255,0.7);
#         text-align: center;
#     }
#     .hint-box code {
#         color: rgba(255,255,255,0.9);
#         background: rgba(255,255,255,0.1);
#         border-radius: 0.25rem;
#         padding: 0.05rem 0.3rem;
#     }

#     .divider-label { text-align:center; color:rgba(255,255,255,0.55); font-size:0.82rem; margin:0.75rem 0; }
# </style>
# """, unsafe_allow_html=True)

# # ── Session state ──────────────────────────────────────────────────────────────
# for key, default in [
#     ("selected_role", None),
#     ("login_error",   None),
#     ("pw_attempts",   0),
# ]:
#     if key not in st.session_state:
#         st.session_state[key] = default

# # ── Helpers ────────────────────────────────────────────────────────────────────

# def check_backend() -> bool:
#     try:
#         return requests.get(f"{BACKEND_URL}/health", timeout=4).status_code == 200
#     except Exception:
#         return False

# def get_enrollment(identity: str) -> dict:
#     try:
#         r = requests.get(f"{BACKEND_URL}/enrollment/{identity}", timeout=4)
#         return r.json() if r.ok else {}
#     except Exception:
#         return {}

# def verify_credentials(role: str, email: str, password: str) -> tuple[bool, str]:
#     """
#     Returns (ok, error_message).
#     Checks email first, then password, so the error message is specific.
#     """
#     creds = CREDENTIALS[role]
#     if email.strip().lower() != creds["email"].lower():
#         return False, "Email address not recognised for this role."
#     if password != creds["password"]:
#         return False, "Incorrect password. Please try again."
#     return True, ""

# # ── Main ───────────────────────────────────────────────────────────────────────

# def main():
#     backend_ok    = check_backend()
#     sender_status = get_enrollment("sender")   if backend_ok else {}
#     recv_status   = get_enrollment("receiver") if backend_ok else {}
#     sender_ready  = sender_status.get("fully_enrolled", False)
#     recv_ready    = recv_status.get("fully_enrolled",   False)

#     # ── Header ─────────────────────────────────────────────────────────────────
#     st.markdown("""
#     <div style="text-align:center; padding:1.8rem 0 0.5rem;">
#         <div style="font-size:3rem; margin-bottom:0.2rem;">🔐</div>
#         <div class="login-title">QKD Secure Comm</div>
#         <div class="login-subtitle">
#             Quantum Key Distribution · Biometric Auth · AES-256-GCM
#         </div>
#     </div>
#     """, unsafe_allow_html=True)

#     # Backend pill
#     _, mid, _ = st.columns([1, 2, 1])
#     with mid:
#         if backend_ok:
#             st.markdown('<div style="text-align:center;margin-bottom:0.35rem;">'
#                         '<span class="status-online">● Backend Online</span></div>',
#                         unsafe_allow_html=True)
#         else:
#             st.markdown('<div style="text-align:center;margin-bottom:0.35rem;">'
#                         '<span class="status-offline">● Backend Offline</span></div>',
#                         unsafe_allow_html=True)

#     if not backend_ok:
#         st.error("**Backend not running.**\n\n"
#                  "```\nuvicorn main:app --host 0.0.0.0 --port 8000\n```")
#         return

#     _, col, _ = st.columns([0.5, 9, 0.5])
#     with col:

#         # ══════════════════════════════════════════════════════════════
#         # STEP 1 — Role selection
#         # ══════════════════════════════════════════════════════════════
#         if st.session_state.selected_role is None:

#             st.markdown(
#                 "<p style='color:rgba(255,255,255,0.42);font-size:0.83rem;"
#                 "margin-bottom:0.85rem;'>Select your role to continue</p>",
#                 unsafe_allow_html=True
#             )

#             for role, label, ready in [
#                 ("sender",   "Sender",   sender_ready),
#                 ("receiver", "Receiver", recv_ready),
#             ]:
#                 grad, shadow = ROLE_GRADS[role]
#                 icon         = ROLE_ICONS[role]
#                 desc = "Encrypt & send files" if role == "sender" else "Receive & decrypt files"
#                 badge = "" if ready else "<span class='warn-badge'>⚠ Not enrolled</span>"

#                 st.markdown(f"""
#                 <div class="role-card"
#                      style="background:linear-gradient({grad});
#                             box-shadow:0 4px 18px {shadow};">
#                     <div style="font-size:1.8rem;">{icon}</div>
#                     <div style="font-size:1.05rem;font-weight:800;color:#fff;margin-top:0.2rem;">
#                         {label} {badge}
#                     </div>
#                     <div style="font-size:0.75rem;color:rgba(255,255,255,0.6);margin-top:0.12rem;">
#                         {desc}
#                     </div>
#                 </div>
#                 """, unsafe_allow_html=True)

#                 if st.button(f"{icon}  Login as {label}",
#                              key=f"btn_{role}", use_container_width=True):
#                     st.session_state.selected_role = role
#                     st.session_state.login_error   = None
#                     st.session_state.pw_attempts   = 0
#                     st.rerun()

#                 st.markdown("<div style='height:0.35rem'></div>",
#                             unsafe_allow_html=True)

#                 st.markdown("<div style='height:0.35rem'></div>",
#                             unsafe_allow_html=True)

#         # ══════════════════════════════════════════════════════════════
#         # STEP 2 — Email + Password form
#         # ══════════════════════════════════════════════════════════════
#         else:
#             role     = st.session_state.selected_role
#             icon     = ROLE_ICONS[role]
#             grad, _  = ROLE_GRADS[role]
#             redirect = REDIRECT_URLS[role]
#             attempts = st.session_state.pw_attempts

#             # Role banner
#             st.markdown(f"""
#             <div class="pw-banner" style="background:linear-gradient({grad});">
#                 <div style="font-size:1.7rem;">{icon}</div>
#                 <div style="font-size:1rem;font-weight:800;color:#fff;margin-top:0.2rem;">
#                     {role.capitalize()} Login
#                 </div>
#                 <div style="font-size:0.74rem;color:rgba(255,255,255,0.62);">
#                     Enter your email and password to continue
#                 </div>
#             </div>
#             """, unsafe_allow_html=True)

#             # ── Lockout guard ──────────────────────────────────────────
#             if attempts >= 5:
#                 st.error("🔒 Too many failed attempts. Contact the administrator.")
#                 if st.button("← Start Over", key="btn_lockout_back",
#                              use_container_width=True):
#                     st.session_state.selected_role = None
#                     st.session_state.pw_attempts   = 0
#                     st.session_state.login_error   = None
#                     st.rerun()
#                 return

#             # ── Email field ────────────────────────────────────────────
#             email = st.text_input(
#                 "Email Address",
#                 placeholder=f"e.g. {CREDENTIALS[role]['email']}",
#                 key="email_input"
#             )

#             # ── Password field ─────────────────────────────────────────
#             password = st.text_input(
#                 "Password",
#                 type="password",
#                 placeholder="Enter your password...",
#                 key="pw_input"
#             )

#             # ── Error from previous attempt ────────────────────────────
#             if st.session_state.login_error:
#                 remaining = 5 - attempts
#                 st.error(
#                     f"❌ {st.session_state.login_error}  —  "
#                     f"{remaining} attempt{'s' if remaining != 1 else ''} remaining"
#                 )

#             # ── Action buttons ─────────────────────────────────────────
#             c1, c2 = st.columns([3, 1])
#             with c1:
#                 login_clicked = st.button(
#                     f"🔓  Sign In as {role.capitalize()}",
#                     key="btn_submit", type="primary",
#                     use_container_width=True
#                 )
#             with c2:
#                 if st.button("← Back", key="btn_back",
#                              use_container_width=True):
#                     st.session_state.selected_role = None
#                     st.session_state.login_error   = None
#                     st.session_state.pw_attempts   = 0
#                     st.rerun()

#             # ── Handle submit ──────────────────────────────────────────
#             if login_clicked:
#                 if not email.strip():
#                     st.session_state.login_error = "Email address cannot be empty."
#                     st.rerun()
#                 elif not password:
#                     st.session_state.login_error = "Password cannot be empty."
#                     st.rerun()
#                 else:
#                     ok, err_msg = verify_credentials(role, email, password)
#                     if ok:
#                         # ✅ Success
#                         st.session_state.login_error   = None
#                         st.session_state.pw_attempts   = 0
#                         st.success(f"✅ Welcome, {role.capitalize()}! Redirecting...")
#                         redirect_with_role = f"{redirect}?role={role}"
#                         st.markdown(
#                             f'<meta http-equiv="refresh" content="1;url={redirect_with_role}">',
#                             unsafe_allow_html=True
#                         )
#                         st.info(f"If not redirected automatically → {redirect_with_role}")
#                     else:
#                         # ❌ Failure
#                         st.session_state.pw_attempts += 1
#                         st.session_state.login_error   = err_msg
#                         st.rerun()



# if __name__ == "__main__":
#     main()

"""
Login App — QKD Multimodal Secure Communication
Port 8501 | Gatekeeper UI

Handles user login, registration, and routing to main app or enrollment.
Integrates with all three innovations via session state flags.
"""

import streamlit as st
import hashlib
import json
import os
import time
from pathlib import Path

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="QSec — Quantum Secure Gateway",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── CSS — Dark quantum aesthetic ──────────────────────────────────────────────
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
    --cyan-dim:   rgba(0, 200, 255, 0.12);
    --green:      #00ff9d;
    --green-dim:  rgba(0, 255, 157, 0.10);
    --red:        #ff3c6e;
    --text-1:     #e8f4ff;
    --text-2:     #7ba8c4;
    --text-3:     #3d6278;
    --mono:       'Share Tech Mono', monospace;
    --head:       'Rajdhani', sans-serif;
    --body:       'Exo 2', sans-serif;
}

/* Global reset */
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

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 1rem !important; max-width: 520px !important; margin: 0 auto; }

/* ── Hero header ── */
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
.qsec-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
}
.qsec-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    opacity: 0.6;
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
.stTextInput > div > div > input:focus,
.stSelectbox > div > div > div:focus {
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
.stSuccess > div, .element-container .stAlert[data-baseweb="notification"] {
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
    border-left: 3px solid #ffb400 !important;
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

/* ── Status badges ── */
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

/* ── Innovation tags ── */
.inno-row {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.8rem 0;
}

/* ── Divider ── */
.qdivider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.5rem 0;
}

/* ── Footer ── */
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

/* ── Tab styling ── */
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

/* ── Spinner ── */
.stSpinner > div { border-top-color: var(--cyan) !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
</style>
""", unsafe_allow_html=True)

# ── User store ────────────────────────────────────────────────────────────────
USER_DB = Path("data/users.json")
USER_DB.parent.mkdir(parents=True, exist_ok=True)

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
    users = load_users()
    return users.get(username, {}).get("enrolled", False)

# ── Session defaults ──────────────────────────────────────────────────────────
for key, val in {
    "authenticated": False,
    "username": None,
    "role": None,
    "enrolled": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = val

# ── Hero ──────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="qsec-hero">
    <div class="qsec-logo">◈ Quantum Secure Communications ◈</div>
    <h1 class="qsec-title">Q<span>SEC</span></h1>
    <div class="qsec-sub">BB84 · AES-256-GCM · Multimodal Biometrics</div>
</div>
""", unsafe_allow_html=True)

# ── Innovation badges ─────────────────────────────────────────────────────────
st.markdown("""
<div class="inno-row">
    <span class="badge badge-cyan">BQES · Biometric Entropy Seeding</span>
    <span class="badge badge-green">QNLD · Quantum Noise Liveness</span>
    <span class="badge badge-cyan">Adaptive Re-keying</span>
</div>
""", unsafe_allow_html=True)

# ── Authenticated view ────────────────────────────────────────────────────────
if st.session_state.authenticated:
    enrolled = is_enrolled(st.session_state.username)

    st.markdown(f"""
    <div class="qsec-card">
        <div class="card-title">◈ Session Active</div>
        <span class="badge badge-green">● Authenticated</span>
        <span class="badge badge-cyan">{st.session_state.role.upper()}</span>
        <span class="badge badge-gray">{st.session_state.username}</span>
        {'<span class="badge badge-green">Biometrics Enrolled</span>' if enrolled else '<span class="badge badge-amber">Enrollment Optional</span>'}
    </div>
    """, unsafe_allow_html=True)

    # Always allow direct access — no enrollment gate
    st.success("✓  Authentication successful. Access granted.")

    col1, col2 = st.columns(2)
    uname = st.session_state.username or ""
    urole = st.session_state.role or "sender"
    ops_url = f"http://192.168.29.165:8502?auth_user={uname}&auth_role={urole}"
    with col1:
        st.markdown('<div class="btn-primary">', unsafe_allow_html=True)
        if st.button("Open Operations Panel →", key="goto_main"):
            st.markdown(f'<meta http-equiv="refresh" content="0;url={ops_url}">', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
    with col2:
        if st.button("Sign Out", key="logout"):
            for k in ["authenticated", "username", "role", "enrolled"]:
                st.session_state[k] = None if k not in ("authenticated", "enrolled") else False
            st.rerun()

    # Enrollment shown as optional upgrade, not a blocker
    if not enrolled:
        st.markdown('<hr class="qdivider">', unsafe_allow_html=True)
        st.markdown("""
        <div class="qsec-card">
            <div class="card-title">◈ Optional — Biometric Enrollment</div>
            <div style="font-family:var(--mono);font-size:0.72rem;color:var(--text-2);line-height:2.1;">
                Enroll your face and fingerprint to unlock:<br>
                &nbsp;· &nbsp;<span style="color:var(--cyan)">BQES</span> — Identity-bound BB84 key generation<br>
                &nbsp;· &nbsp;<span style="color:var(--cyan)">QNLD</span> — Quantum noise liveness detection<br>
                &nbsp;· &nbsp;<span style="color:var(--cyan)">ARK &nbsp;</span> — Adaptive re-keying on biometric drift
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("→ Go to Enrollment Center (Port 8502)", key="goto_enroll"):
            st.markdown(f'<meta http-equiv="refresh" content="0;url={ops_url}">', unsafe_allow_html=True)
    else:
        st.info("→  Biometrics active. All three innovations (BQES · QNLD · ARK) will run during operations.")

# ── Login / Register ──────────────────────────────────────────────────────────
else:
    tab_login, tab_register = st.tabs(["  Sign In  ", "  Register  "])

    with tab_login:
        st.markdown('<div class="qsec-card"><div class="card-title">◈ Identity Verification</div>', unsafe_allow_html=True)

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
                with st.spinner("Initialising secure session..."):
                    time.sleep(0.6)
                st.success(f"✓  Welcome back, {username}.")
                time.sleep(0.5)
                st.rerun()
            else:
                st.error("✗  Invalid credentials. Access denied.")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_register:
        st.markdown('<div class="qsec-card"><div class="card-title">◈ New Operator Registration</div>', unsafe_allow_html=True)

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
                st.success(f"✓  Operator '{new_user}' registered as {role}.")
                st.info("→  Sign in to access the Operations Panel. Biometric enrollment is optional.")
            else:
                st.error(f"✗  Username '{new_user}' already exists.")

# ── System status panel ───────────────────────────────────────────────────────
st.markdown('<hr class="qdivider">', unsafe_allow_html=True)
st.markdown('<div class="qsec-card"><div class="card-title">◈ System Status</div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<span class="badge badge-green">● BB84 Active</span>', unsafe_allow_html=True)
with col2:
    st.markdown('<span class="badge badge-green">● AES-256-GCM</span>', unsafe_allow_html=True)
with col3:
    st.markdown('<span class="badge badge-cyan">● BQES v2.0</span>', unsafe_allow_html=True)

users = load_users()
total = len(users)
enrolled_count = sum(1 for u in users.values() if u.get("enrolled"))
st.markdown(f"""
<div style="margin-top:1rem; font-family:var(--mono); font-size:0.72rem; color:var(--text-2); line-height:2;">
    REGISTERED OPERATORS &nbsp;·&nbsp; <span style="color:var(--cyan)">{total}</span><br>
    ENROLLED BIOMETRICS  &nbsp;·&nbsp; <span style="color:var(--green)">{enrolled_count}</span><br>
    PROTOCOL &nbsp;·&nbsp; <span style="color:var(--cyan)">BB84-BQES-QNLD-v2</span>
</div>
""", unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="qfooter">
    QSEC MULTIMODAL SECURE COMM · BB84 + AES-256-GCM · BQES · QNLD · ADAPTIVE RE-KEYING<br>
    FOR AUTHORISED OPERATORS ONLY · ALL SESSIONS MONITORED AND LOGGED
</div>
""", unsafe_allow_html=True)