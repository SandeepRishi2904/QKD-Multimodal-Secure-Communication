"""
QKD Multimodal Secure Communication System - Login Page

Flow:
  1. User selects role (Sender / Receiver)
  2. Email + Password form appears for that role
  3. Both must match the credentials defined in CREDENTIALS below
  4. Correct → redirect to the respective Streamlit app
  5. Wrong  → error message, max 5 attempts then lockout

To change credentials, edit the CREDENTIALS dict below.

Run: streamlit run login_app.py --server.port 8500
"""
import requests
from datetime import datetime
import streamlit as st

st.set_page_config(
    page_title="QKD Secure Login",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed"
)

BACKEND_URL = "http://localhost:8000"

# ── Credentials — edit here to change email / password ────────────────────────
# Each role has its own independent email + password pair.
CREDENTIALS = {
    "sender": {
        "email":    "rishikesh95430@gmail.com",
        "password": "sender123",
    },
    "receiver": {
        "email":    "receiver@qkd.local",
        "password": "receiver123",
    },
}

REDIRECT_URLS = {
    "sender":   "http://localhost:8501",
    "receiver": "http://localhost:8502",
}
ROLE_ICONS = {"sender": "📤", "receiver": "📥"}
ROLE_GRADS = {
    "sender":   ("135deg, #667eea 0%, #764ba2 100%", "rgba(102,126,234,0.3)"),
    "receiver": ("135deg, #11998e 0%, #38ef7d 100%", "rgba(17,153,142,0.3)"),
}

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    #MainMenu { visibility: hidden; }
    footer     { visibility: hidden; }
    header     { visibility: hidden; }

    .stApp {
        background: linear-gradient(135deg, #0f0c29 0%, #1a1a4e 50%, #24243e 100%);
        min-height: 100vh;
    }

    /* ── Typography ── */
    .login-title {
        font-size: 2rem; font-weight: 800; text-align: center;
        color: #ffffff; letter-spacing: 0.5px; margin-bottom: 0.2rem;
    }
    .login-subtitle {
        text-align: center; color: rgba(255,255,255,0.48);
        font-size: 0.86rem; margin-bottom: 0.5rem;
    }

    /* ── Role cards ── */
    .role-card {
        border-radius: 1rem; padding: 1.2rem 1rem;
        margin-bottom: 0.5rem; text-align: center;
    }
    .pw-banner {
        border-radius: 0.85rem; padding: 0.9rem 1.2rem;
        text-align: center; margin-bottom: 1rem;
    }

    /* ── Streamlit overrides ── */
    .stButton > button {
        border-radius: 0.75rem !important; font-weight: 700 !important;
        height: 3rem !important; font-size: 0.95rem !important; width: 100% !important;
    }
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.07) !important;
        border: 1px solid rgba(255,255,255,0.18) !important;
        border-radius: 0.6rem !important; color: #ffffff !important;
        font-size: 0.95rem !important; padding: 0.65rem 0.9rem !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #667eea !important;
        box-shadow: 0 0 0 2px rgba(102,126,234,0.25) !important;
    }
    .stTextInput label {
        color: rgba(255,255,255,0.55) !important;
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        margin-bottom: 0.2rem !important;
    }

    /* ── Status pills ── */
    .status-online {
        display:inline-block; background:rgba(56,239,125,0.15); color:#38ef7d;
        border:1px solid rgba(56,239,125,0.3); border-radius:2rem;
        padding:0.2rem 0.8rem; font-size:0.75rem; font-weight:600;
    }
    .status-offline {
        display:inline-block; background:rgba(255,82,82,0.15); color:#ff5252;
        border:1px solid rgba(255,82,82,0.3); border-radius:2rem;
        padding:0.2rem 0.8rem; font-size:0.75rem; font-weight:600;
    }
    .warn-badge {
        display:inline-block; background:rgba(255,193,7,0.15); color:#ffc107;
        border:1px solid rgba(255,193,7,0.3); border-radius:2rem;
        padding:0.1rem 0.55rem; font-size:0.68rem; font-weight:600;
        margin-left:0.3rem; vertical-align:middle;
    }

    /* ── Bottom metric row ── */
    .metric-row { display:flex; gap:0.5rem; margin-top:1.1rem; }
    .metric-box {
        flex:1; background:rgba(255,255,255,0.05); border-radius:0.6rem;
        padding:0.55rem; text-align:center;
    }
    .metric-label { color:rgba(255,255,255,0.35); font-size:0.64rem; text-transform:uppercase; letter-spacing:0.4px; }
    .metric-value { color:#fff; font-size:0.9rem; font-weight:700; margin-top:0.15rem; }

    /* ── Info / port strip ── */
    .info-strip {
        background:rgba(102,126,234,0.1); border-left:3px solid #667eea;
        border-radius:0 0.5rem 0.5rem 0; padding:0.6rem 0.85rem;
        color:rgba(255,255,255,0.6); font-size:0.77rem; margin-top:1.25rem;
    }

    /* ── Credential hint box ── */
    .hint-box {
        background: rgba(255,255,255,0.04);
        border: 1px dashed rgba(255,255,255,0.12);
        border-radius: 0.6rem;
        padding: 0.6rem 0.85rem;
        margin-top: 0.75rem;
        font-size: 0.75rem;
        color: rgba(255,255,255,0.35);
        text-align: center;
    }
    .hint-box code {
        color: rgba(255,255,255,0.55);
        background: rgba(255,255,255,0.07);
        border-radius: 0.25rem;
        padding: 0.05rem 0.3rem;
    }

    .divider-label { text-align:center; color:rgba(255,255,255,0.28); font-size:0.78rem; margin:0.75rem 0; }
</style>
""", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
for key, default in [
    ("selected_role", None),
    ("login_error",   None),
    ("pw_attempts",   0),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── Helpers ────────────────────────────────────────────────────────────────────

def check_backend() -> bool:
    try:
        return requests.get(f"{BACKEND_URL}/health", timeout=4).status_code == 200
    except Exception:
        return False

def get_enrollment(identity: str) -> dict:
    try:
        r = requests.get(f"{BACKEND_URL}/enrollment/{identity}", timeout=4)
        return r.json() if r.ok else {}
    except Exception:
        return {}

def verify_credentials(role: str, email: str, password: str) -> tuple[bool, str]:
    """
    Returns (ok, error_message).
    Checks email first, then password, so the error message is specific.
    """
    creds = CREDENTIALS[role]
    if email.strip().lower() != creds["email"].lower():
        return False, "Email address not recognised for this role."
    if password != creds["password"]:
        return False, "Incorrect password. Please try again."
    return True, ""

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    backend_ok    = check_backend()
    sender_status = get_enrollment("sender")   if backend_ok else {}
    recv_status   = get_enrollment("receiver") if backend_ok else {}
    sender_ready  = sender_status.get("fully_enrolled", False)
    recv_ready    = recv_status.get("fully_enrolled",   False)

    # ── Header ─────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center; padding:1.8rem 0 0.5rem;">
        <div style="font-size:3rem; margin-bottom:0.2rem;">🔐</div>
        <div class="login-title">QKD Secure Comm</div>
        <div class="login-subtitle">
            Quantum Key Distribution · Biometric Auth · AES-256-GCM
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Backend pill
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        if backend_ok:
            st.markdown('<div style="text-align:center;margin-bottom:0.35rem;">'
                        '<span class="status-online">● Backend Online</span></div>',
                        unsafe_allow_html=True)
        else:
            st.markdown('<div style="text-align:center;margin-bottom:0.35rem;">'
                        '<span class="status-offline">● Backend Offline</span></div>',
                        unsafe_allow_html=True)

    if not backend_ok:
        st.error("**Backend not running.**\n\n"
                 "```\nuvicorn main:app --host 0.0.0.0 --port 8000\n```")
        return

    _, col, _ = st.columns([0.5, 9, 0.5])
    with col:

        # ══════════════════════════════════════════════════════════════
        # STEP 1 — Role selection
        # ══════════════════════════════════════════════════════════════
        if st.session_state.selected_role is None:

            st.markdown(
                "<p style='color:rgba(255,255,255,0.42);font-size:0.83rem;"
                "margin-bottom:0.85rem;'>Select your role to continue</p>",
                unsafe_allow_html=True
            )

            for role, label, ready in [
                ("sender",   "Sender",   sender_ready),
                ("receiver", "Receiver", recv_ready),
            ]:
                grad, shadow = ROLE_GRADS[role]
                icon         = ROLE_ICONS[role]
                desc = "Encrypt & send files" if role == "sender" else "Receive & decrypt files"
                badge = "" if ready else "<span class='warn-badge'>⚠ Not enrolled</span>"

                st.markdown(f"""
                <div class="role-card"
                     style="background:linear-gradient({grad});
                            box-shadow:0 4px 18px {shadow};">
                    <div style="font-size:1.8rem;">{icon}</div>
                    <div style="font-size:1.05rem;font-weight:800;color:#fff;margin-top:0.2rem;">
                        {label} {badge}
                    </div>
                    <div style="font-size:0.75rem;color:rgba(255,255,255,0.6);margin-top:0.12rem;">
                        {desc}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if st.button(f"{icon}  Login as {label}",
                             key=f"btn_{role}", use_container_width=True):
                    if not ready:
                        st.warning(f"⚠️ {label} biometrics are not enrolled. "
                                   "Go to the Enrollment Center first.")
                    else:
                        st.session_state.selected_role = role
                        st.session_state.login_error   = None
                        st.session_state.pw_attempts   = 0
                        st.rerun()

                st.markdown("<div style='height:0.35rem'></div>",
                            unsafe_allow_html=True)

                st.markdown("<div style='height:0.35rem'></div>",
                            unsafe_allow_html=True)

        # ══════════════════════════════════════════════════════════════
        # STEP 2 — Email + Password form
        # ══════════════════════════════════════════════════════════════
        else:
            role     = st.session_state.selected_role
            icon     = ROLE_ICONS[role]
            grad, _  = ROLE_GRADS[role]
            redirect = REDIRECT_URLS[role]
            attempts = st.session_state.pw_attempts

            # Role banner
            st.markdown(f"""
            <div class="pw-banner" style="background:linear-gradient({grad});">
                <div style="font-size:1.7rem;">{icon}</div>
                <div style="font-size:1rem;font-weight:800;color:#fff;margin-top:0.2rem;">
                    {role.capitalize()} Login
                </div>
                <div style="font-size:0.74rem;color:rgba(255,255,255,0.62);">
                    Enter your email and password to continue
                </div>
            </div>
            """, unsafe_allow_html=True)

            # ── Lockout guard ──────────────────────────────────────────
            if attempts >= 5:
                st.error("🔒 Too many failed attempts. Contact the administrator.")
                if st.button("← Start Over", key="btn_lockout_back",
                             use_container_width=True):
                    st.session_state.selected_role = None
                    st.session_state.pw_attempts   = 0
                    st.session_state.login_error   = None
                    st.rerun()
                return

            # ── Email field ────────────────────────────────────────────
            email = st.text_input(
                "Email Address",
                placeholder=f"e.g. {CREDENTIALS[role]['email']}",
                key="email_input"
            )

            # ── Password field ─────────────────────────────────────────
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password...",
                key="pw_input"
            )

            # ── Error from previous attempt ────────────────────────────
            if st.session_state.login_error:
                remaining = 5 - attempts
                st.error(
                    f"❌ {st.session_state.login_error}  —  "
                    f"{remaining} attempt{'s' if remaining != 1 else ''} remaining"
                )

            # ── Action buttons ─────────────────────────────────────────
            c1, c2 = st.columns([3, 1])
            with c1:
                login_clicked = st.button(
                    f"🔓  Sign In as {role.capitalize()}",
                    key="btn_submit", type="primary",
                    use_container_width=True
                )
            with c2:
                if st.button("← Back", key="btn_back",
                             use_container_width=True):
                    st.session_state.selected_role = None
                    st.session_state.login_error   = None
                    st.session_state.pw_attempts   = 0
                    st.rerun()

            # ── Handle submit ──────────────────────────────────────────
            if login_clicked:
                if not email.strip():
                    st.session_state.login_error = "Email address cannot be empty."
                    st.rerun()
                elif not password:
                    st.session_state.login_error = "Password cannot be empty."
                    st.rerun()
                else:
                    ok, err_msg = verify_credentials(role, email, password)
                    if ok:
                        # ✅ Success
                        st.session_state.login_error   = None
                        st.session_state.pw_attempts   = 0
                        st.success(f"✅ Welcome, {role.capitalize()}! Redirecting...")
                        st.markdown(
                            f'<meta http-equiv="refresh" content="1;url={redirect}">',
                            unsafe_allow_html=True
                        )
                        st.info(f"If not redirected automatically → {redirect}")
                    else:
                        # ❌ Failure
                        st.session_state.pw_attempts += 1
                        st.session_state.login_error   = err_msg
                        st.rerun()

            # ── Default credentials hint (first clean visit only) ──────
            if attempts == 0 and not st.session_state.login_error:
                st.markdown(
                    f"<div class='hint-box'>"
                    f"Default credentials for <strong>{role}</strong>: &nbsp;"
                    f"<code>{CREDENTIALS[role]['email']}</code> &nbsp;/&nbsp; "
                    f"<code>{CREDENTIALS[role]['password']}</code>"
                    f"</div>",
                    unsafe_allow_html=True
                )

if __name__ == "__main__":
    main()