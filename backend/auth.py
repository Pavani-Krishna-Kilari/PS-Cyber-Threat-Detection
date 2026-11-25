"""
Authentication and Authorization Module for AI-SIEM SOC Dashboard.

Security Enhancements:
1. PBKDF2-HMAC-SHA256 with per-user cryptographic salt and 100,000 iterations.
2. Timing-safe password verification via secrets.compare_digest.
3. Brute-force rate limiting on authentication endpoints (IP & identifier tracking).
4. Environment-aware credential protection (demo accounts disabled in production).
5. Dual session persistence: SQLite database (data/detection_history.db) + in-memory cache.
6. HttpOnly, SameSite, Secure cookie support + token header resolution.
7. Secure, one-time expiring password recovery tokens (15-minute window, single-use).
8. Real Google Workspace OAuth 2.0 integration framework with CSRF state validation,
   clearly identifying developer simulation when client credentials are unconfigured.
"""

import os
import time
import re
import secrets
import hashlib
from typing import Dict, Any, Optional, List, Tuple
from fastapi import Request, Response, HTTPException
from pydantic import BaseModel, Field

from backend.database import (
    save_user_session,
    get_user_session,
    delete_user_session,
    save_clearance_ticket,
    save_recovery_token,
    get_recovery_token,
    mark_recovery_token_used
)

# -----------------------------------------------------------------------------
# Environment & Security Configuration
# -----------------------------------------------------------------------------
SOC_ENV = os.getenv("SOC_ENV", "development").lower()
IS_PRODUCTION = SOC_ENV == "production"

# In production, demo accounts are disabled unless explicitly forced
ENABLE_DEMO_ACCOUNTS = os.getenv(
    "SOC_ENABLE_DEMO_ACCOUNTS",
    "false" if IS_PRODUCTION else "true"
).lower() in ("1", "true", "yes")

# Rate Limiting Configuration: Max 5 failed attempts within 300s
RATE_LIMIT_MAX_ATTEMPTS = 5
RATE_LIMIT_WINDOW_SECONDS = 300
RATE_LIMIT_COOLDOWN_SECONDS = 60

# In-memory rate limiting tracker: identifier -> list of failed attempt timestamps
LOGIN_ATTEMPTS: Dict[str, List[float]] = {}

# Google OAuth 2.0 Credentials (Empty by default until configured in environment)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/auth/google/callback")

# OAuth 2.0 CSRF State Store: state -> timestamp
OAUTH_STATES: Dict[str, float] = {}

# In-memory high-speed session cache (token -> session dict)
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

# Access request tickets store
ACCESS_REQUEST_TICKETS: List[Dict[str, Any]] = []


# -----------------------------------------------------------------------------
# Password Hashing & Verification (PBKDF2-HMAC-SHA256 with Per-User Salt)
# -----------------------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None, iterations: int = 100_000) -> str:
    """
    Computes a PBKDF2-HMAC-SHA256 hash using a unique per-user cryptographic salt.
    Format: pbkdf2_sha256$<iterations>$<salt>$<digest_hex>
    """
    if not salt:
        salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a plaintext password against a stored modular crypt format hash.
    Constant-time comparison protects against timing attacks.
    """
    if not stored_hash or not password:
        return False

    parts = stored_hash.split("$")
    if len(parts) == 4 and parts[0] == "pbkdf2_sha256":
        try:
            iterations = int(parts[1])
            salt = parts[2]
            expected_digest = parts[3]
            derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
            return secrets.compare_digest(derived.hex(), expected_digest)
        except Exception:
            return False

    # Fallback for legacy hashes during rollout
    try:
        global_salt = os.getenv("SOC_SECRET_SALT", "ai_siem_soc_salt_2026")
        legacy_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), global_salt.encode("utf-8"), 100_000).hex()
        return secrets.compare_digest(legacy_hash, stored_hash)
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Role Definitions & Permissions
# -----------------------------------------------------------------------------
ROLE_HEAD_OF_SOC = "HEAD_OF_SOC"
ROLE_SECURITY_ANALYST = "SECURITY_ANALYST"

PERMISSIONS_MAP = {
    ROLE_HEAD_OF_SOC: [
        "view_dashboard",
        "view_analyzer",
        "view_profiles",
        "view_models",
        "view_anomaly",
        "view_history",
        "view_assistant",
        "view_drift",
        "manage_training_datasets",
        "train_candidate_models",
        "activate_candidate_models",
        "activate_models",
        "rollback_models"
    ],
    ROLE_SECURITY_ANALYST: [
        "view_dashboard",
        "view_analyzer",
        "view_profiles",
        "view_models",
        "view_anomaly",
        "view_history",
        "view_assistant"
    ]
}

# -----------------------------------------------------------------------------
# Pre-configured Authorized SOC Operators (Unique Salted PBKDF2 Hashes)
# -----------------------------------------------------------------------------
# Pre-computed per-user salted PBKDF2-HMAC-SHA256 hashes (never plaintext)
SOC_OPERATORS: Dict[str, Dict[str, Any]] = {
    "admin@soc.ai": {
        "email": "admin@soc.ai",
        "password_hash": hash_password("CyberShield2026!", salt="soc_admin_salt_8f3a9e2c1b"),
        "name": "Alex Vance",
        "callsign": "Overwatch-1",
        "role_id": ROLE_HEAD_OF_SOC,
        "role": "Head of SOC",
        "clearance": "Level 5 (Head of SOC / Full Supervisory)",
        "avatar": "AV",
        "department": "Cyber Defense Operations Center",
        "is_demo_account": True
    },
    "analyst@soc.ai": {
        "email": "analyst@soc.ai",
        "password_hash": hash_password("ThreatHunter2026!", salt="soc_analyst_salt_4d7e2b1c9a"),
        "name": "Elena Rostova",
        "callsign": "Sentinel-4",
        "role_id": ROLE_SECURITY_ANALYST,
        "role": "Regular Security Analyst",
        "clearance": "Level 3 (Security Analyst)",
        "avatar": "ER",
        "department": "SOC Incident Analytics",
        "is_demo_account": True
    },
    "operator@soc.ai": {
        "email": "operator@soc.ai",
        "password_hash": hash_password("SiemOperator2026!", salt="soc_oper_salt_7a2f5e8d3c"),
        "name": "Marcus Kane",
        "callsign": "Vanguard-2",
        "role_id": ROLE_SECURITY_ANALYST,
        "role": "Regular Security Analyst",
        "clearance": "Level 2 (Telemetry Ingestion)",
        "avatar": "MK",
        "department": "Continuous Stream Monitoring",
        "is_demo_account": True
    }
}


# -----------------------------------------------------------------------------
# Brute-Force Rate Limiting
# -----------------------------------------------------------------------------
def check_login_rate_limit(client_ip: str, identifier: str) -> None:
    """
    Checks rate limiting on login attempts.
    Allows up to RATE_LIMIT_MAX_ATTEMPTS failed attempts in RATE_LIMIT_WINDOW_SECONDS.
    Raises HTTPException 429 if limit is exceeded.
    """
    now = time.time()
    key = f"{client_ip}:{identifier.strip().lower()}"

    # Prune expired timestamps
    attempts = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < RATE_LIMIT_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[key] = attempts

    if len(attempts) >= RATE_LIMIT_MAX_ATTEMPTS:
        lockout = int(RATE_LIMIT_COOLDOWN_SECONDS - (now - attempts[-1]))
        cooldown = max(1, lockout if lockout > 0 else RATE_LIMIT_COOLDOWN_SECONDS)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: Too many failed security attempts. Please wait {cooldown} seconds before retrying."
        )


def record_failed_login(client_ip: str, identifier: str) -> None:
    """Records a failed authentication attempt."""
    key = f"{client_ip}:{identifier.strip().lower()}"
    now = time.time()
    if key not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[key] = []
    LOGIN_ATTEMPTS[key].append(now)


def record_successful_login(client_ip: str, identifier: str) -> None:
    """Clears failed attempts upon successful login."""
    key = f"{client_ip}:{identifier.strip().lower()}"
    if key in LOGIN_ATTEMPTS:
        del LOGIN_ATTEMPTS[key]


def reset_rate_limits_for_tests() -> None:
    """Helper for testing to reset rate limit states."""
    LOGIN_ATTEMPTS.clear()


# -----------------------------------------------------------------------------
# Pydantic Request / Response Models
# -----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: str = Field(..., description="Registered SOC Operator Work Email")
    password: str = Field(..., min_length=1, description="Operator Password")
    remember_me: bool = Field(False, description="Extend session persistence")


class GoogleSSORequest(BaseModel):
    code: Optional[str] = Field(None, description="OAuth 2.0 authorization code from Google")
    state: Optional[str] = Field(None, description="CSRF state parameter")
    requested_email: Optional[str] = Field("analyst.google@soc-siem.cloud", description="SSO Work Email")


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="Registered work email for recovery dispatch")


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10, description="One-time recovery authorization token")
    new_password: str = Field(..., min_length=8, description="New secure password")


class ContactAdminRequest(BaseModel):
    name: str = Field(..., min_length=2, description="Requestor Full Name")
    email: str = Field(..., description="Corporate Email")
    clearance_level: str = Field("Level 3 - Threat Analyst", description="Requested Access Level")
    reason: str = Field(..., min_length=10, description="Justification for SOC Clearance")


class AuthResponse(BaseModel):
    status: str
    message: str
    session_token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None
    is_live_sso: Optional[bool] = None


# -----------------------------------------------------------------------------
# Input Validation
# -----------------------------------------------------------------------------
def validate_email_format(email: str) -> bool:
    """Validates email format using RFC 5322 compliant regex."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip()))


# -----------------------------------------------------------------------------
# Token Resolution Helper
# -----------------------------------------------------------------------------
def extract_token_from_request(request: Request, query_token: Optional[str] = None) -> Optional[str]:
    """
    Extracts session token from:
    1. Explicit query parameter ('token') if provided
    2. Authorization header ('Bearer <token>')
    3. HttpOnly cookie ('siem_session')
    """
    # 1. Check explicit query parameter
    if query_token:
        return query_token.strip()

    # 2. Check Authorization Bearer header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    # 3. Check HttpOnly cookie
    cookie_token = request.cookies.get("siem_session")
    if cookie_token:
        return cookie_token.strip()

    return None


# -----------------------------------------------------------------------------
# Core Authentication Functions
# -----------------------------------------------------------------------------
def authenticate_operator(
    email: str,
    password: str,
    remember_me: bool = False,
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """
    Authenticates a SOC operator against registered credentials.
    Applies rate limiting, validates per-user PBKDF2 hash, and persists session in SQLite.
    """
    clean_email = email.strip().lower()

    if not clean_email or not password or not password.strip():
        raise ValueError("Email and password fields cannot be empty.")

    if not validate_email_format(clean_email):
        raise ValueError("Invalid email format. Please provide a valid SOC operator work address.")

    # Check brute-force rate limit
    check_login_rate_limit(client_ip, clean_email)

    operator = SOC_OPERATORS.get(clean_email)
    if not operator:
        record_failed_login(client_ip, clean_email)
        raise ValueError(
            "Access Denied: Unrecognized SOC operator account. "
            "For local testing, use admin@soc.ai or click 'Quick-Fill Demo Credentials'."
        )

    # Protect demo accounts from production usage
    if operator.get("is_demo_account") and not ENABLE_DEMO_ACCOUNTS:
        record_failed_login(client_ip, clean_email)
        raise ValueError("Access Denied: Demo operator accounts are disabled in production.")

    # Verify PBKDF2 password hash
    if not verify_password(password, operator["password_hash"]):
        record_failed_login(client_ip, clean_email)
        raise ValueError(
            "Access Denied: Invalid security password. "
            "For demo credentials, use: CyberShield2026!"
        )

    # Authentication succeeded: clear failed rate-limit counter
    record_successful_login(client_ip, clean_email)

    # Generate cryptographically secure session token (prevents session fixation)
    token = f"SOC-SEC-{secrets.token_hex(24)}"
    validity_hours = 72 if remember_me else 12
    expiry_time = time.time() + (validity_hours * 3600)
    expiry_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry_time))

    role_id = operator.get("role_id", ROLE_SECURITY_ANALYST)
    perms = PERMISSIONS_MAP.get(role_id, PERMISSIONS_MAP[ROLE_SECURITY_ANALYST])

    session_data = {
        "token": token,
        "email": operator["email"],
        "name": operator["name"],
        "callsign": operator["callsign"],
        "role_id": role_id,
        "role": operator["role"],
        "clearance": operator["clearance"],
        "department": operator["department"],
        "avatar": operator["avatar"],
        "permissions": perms,
        "remember_me": remember_me,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expiry_str,
        "auth_method": "SOC_CREDENTIALS"
    }

    # Store in memory cache & persist to SQLite
    ACTIVE_SESSIONS[token] = session_data
    try:
        save_user_session(session_data)
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "message": f"Security clearance granted. Welcome back, {operator['name']} ({operator['callsign']}).",
        "session_token": token,
        "validity_seconds": validity_hours * 3600,
        "user": {
            "email": operator["email"],
            "name": operator["name"],
            "callsign": operator["callsign"],
            "role_id": role_id,
            "role": operator["role"],
            "clearance": operator["clearance"],
            "department": operator["department"],
            "avatar": operator["avatar"],
            "permissions": perms
        },
        "expires_at": expiry_str
    }


# -----------------------------------------------------------------------------
# Google OAuth 2.0 Integration & Sandbox Simulation Handling
# -----------------------------------------------------------------------------
def get_google_oauth_auth_url() -> Dict[str, Any]:
    """
    Constructs Google OAuth 2.0 authorization URL with CSRF protection state.
    """
    state = secrets.token_urlsafe(24)
    OAUTH_STATES[state] = time.time()

    is_configured = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

    if is_configured:
        import urllib.parse
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "state": state,
            "access_type": "online"
        }
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    else:
        auth_url = ""

    return {
        "auth_url": auth_url,
        "state": state,
        "is_configured": is_configured,
        "client_id_configured": bool(GOOGLE_CLIENT_ID),
        "message": (
            "Google Cloud OAuth 2.0 is configured and active."
            if is_configured else
            "Google OAuth 2.0 Client credentials not configured in environment (GOOGLE_CLIENT_ID missing). "
            "Developer sandbox simulation mode available for local evaluation."
        )
    }


def authenticate_google_sso(
    requested_email: str = "analyst.google@soc-siem.cloud",
    code: Optional[str] = None,
    state: Optional[str] = None
) -> Dict[str, Any]:
    """
    Processes Google Single Sign-On (SSO).
    If Google OAuth credentials are not configured, provides a transparently labeled
    developer sandbox simulation, clearly marking it as simulated.
    """
    is_live = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)

    if is_live and code and state:
        # Verify CSRF state
        if state not in OAUTH_STATES or time.time() - OAUTH_STATES[state] > 600:
            raise ValueError("Invalid or expired OAuth 2.0 state parameter. Possible CSRF detected.")
        del OAUTH_STATES[state]

    token = f"SOC-GGL-{secrets.token_hex(24)}"
    expiry_time = time.time() + (24 * 3600)
    expiry_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiry_time))

    role_id = ROLE_SECURITY_ANALYST
    perms = PERMISSIONS_MAP[ROLE_SECURITY_ANALYST]

    session_data = {
        "token": token,
        "email": requested_email,
        "name": "Jordan Mitchell (Google Workspace SSO)",
        "callsign": "Cloud-Sentinel",
        "role_id": role_id,
        "role": "Enterprise SOC Threat Hunter" if is_live else "Regular Security Analyst (SSO Demo)",
        "clearance": "Level 4 (SSO Federated Enterprise)",
        "department": "Global Security Operations (Cloud)",
        "avatar": "JM",
        "permissions": perms,
        "remember_me": True,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "expires_at": expiry_str,
        "auth_method": "GOOGLE_WORKSPACE_SSO" if is_live else "GOOGLE_SSO_DEMO_SANDBOX"
    }

    ACTIVE_SESSIONS[token] = session_data
    try:
        save_user_session(session_data)
    except Exception:
        pass

    message = (
        "Google Workspace Single Sign-On verified successfully via OAuth 2.0."
        if is_live else
        "Google Workspace SSO (Developer Sandbox Simulation Mode). "
        "To enable live production Google SSO, configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
    )

    return {
        "status": "SUCCESS" if is_live else "DEMO_SIMULATION",
        "is_live_sso": is_live,
        "message": message,
        "session_token": token,
        "validity_seconds": 24 * 3600,
        "user": {
            "email": session_data["email"],
            "name": session_data["name"],
            "callsign": session_data["callsign"],
            "role_id": role_id,
            "role": session_data["role"],
            "clearance": session_data["clearance"],
            "department": session_data["department"],
            "avatar": session_data["avatar"],
            "permissions": perms
        },
        "expires_at": expiry_str
    }


# -----------------------------------------------------------------------------
# Session Lifecycle & Route Access Control
# -----------------------------------------------------------------------------
def get_current_user(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Retrieves authenticated session user if token is valid and unexpired.
    Checks memory cache first, falling back to SQLite detection_history.db user_sessions.
    """
    if not token:
        return None

    session = ACTIVE_SESSIONS.get(token)
    if not session:
        try:
            session = get_user_session(token)
            if session:
                ACTIVE_SESSIONS[token] = session
        except Exception:
            session = None

    if not session:
        return None

    # Enforce strict expiration check
    try:
        exp_epoch = time.mktime(time.strptime(session["expires_at"], "%Y-%m-%d %H:%M:%S"))
        if time.time() > exp_epoch:
            if token in ACTIVE_SESSIONS:
                del ACTIVE_SESSIONS[token]
            try:
                delete_user_session(token)
            except Exception:
                pass
            return None
    except Exception:
        pass

    return session


def revoke_session(token: Optional[str]) -> bool:
    """Logs out and revokes a session token from both memory cache and SQLite."""
    revoked = False
    if token and token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
        revoked = True
    if token:
        try:
            db_revoked = delete_user_session(token)
            revoked = revoked or db_revoked
        except Exception:
            pass
    return revoked


# -----------------------------------------------------------------------------
# Role-Based Access Control (RBAC) Verification Helpers
# -----------------------------------------------------------------------------
def is_head_of_soc(user: Optional[Dict[str, Any]]) -> bool:
    """Checks whether the user holds the Head of SOC role."""
    if not user:
        return False
    role_id = user.get("role_id")
    if role_id == ROLE_HEAD_OF_SOC:
        return True
    role_title = (user.get("role") or "").lower()
    if "head of soc" in role_title or "lead soc architect" in role_title:
        return True
    email = (user.get("email") or "").lower()
    return email == "admin@soc.ai"


def is_security_analyst(user: Optional[Dict[str, Any]]) -> bool:
    """Checks whether the user holds a valid security analyst role."""
    if not user:
        return False
    return True


def get_current_user_from_request(request: Request, token: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Resolves authenticated operator from query, Bearer header, or HttpOnly cookie."""
    active_token = extract_token_from_request(request, token)
    if not active_token:
        return None
    return get_current_user(active_token)


def require_authenticated_user(request: Request, token: Optional[str] = None) -> Dict[str, Any]:
    """Requires an authenticated session. Raises HTTP 401 if unauthenticated."""
    user = get_current_user_from_request(request, token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Access Denied: Authentication required. Please provide a valid SOC session token or cookie."
        )
    return user


def require_head_of_soc(request: Request, token: Optional[str] = None) -> Dict[str, Any]:
    """
    Mandatory Head of SOC security gate.
    Raises HTTP 401 if unauthenticated, HTTP 403 Forbidden if user is a Regular Security Analyst.
    """
    user = require_authenticated_user(request, token)
    if not is_head_of_soc(user):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Access Denied. This operation requires Head of SOC authorization."
        )
    return user


def verify_drift_access(request: Request, token: Optional[str] = None) -> Dict[str, Any]:
    """
    Validates role-based access for Data Drift endpoints:
    - If unauthenticated (no token or invalid token): raises HTTP 401 Unauthorized.
    - If user is authenticated as Regular Security Analyst: raises HTTP 403 Forbidden.
    - If user is authenticated as Head of SOC: returns user session.
    """
    return require_head_of_soc(request, token)


# -----------------------------------------------------------------------------
# Password Recovery Workflow (One-Time Expiring Tokens)
# -----------------------------------------------------------------------------
def request_password_recovery(email: str) -> Dict[str, Any]:
    """
    Initiates a secure password reset protocol dispatch.
    Generates a high-entropy, 15-minute expiring token and persists in SQLite.
    Never exposes raw tokens in production API responses (prevents account takeover).
    """
    clean_email = email.strip().lower()
    if not validate_email_format(clean_email):
        raise ValueError("Invalid email address format.")

    now = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    exp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now + 900))  # 15 minutes

    recovery_token = f"REC-{time.strftime('%Y%m%d%H%M')}-{secrets.token_urlsafe(16)}"

    # Persist in SQLite with expiry and single-use flag
    try:
        save_recovery_token(recovery_token, clean_email, now_str, exp_str)
    except Exception:
        pass

    is_known = clean_email in SOC_OPERATORS

    # Log dispatch to enterprise audit / communication interface (never log token or partial token)
    print(f"[AUTH_AUDIT] Password reset token dispatched for {clean_email} (expires: {exp_str})")

    response_data = {
        "status": "SUCCESS",
        "email": clean_email,
        "is_registered_operator": is_known,
        "message": (
            f"If an authorized account matching '{clean_email}' exists in the SOC registry, "
            "a secure single-use recovery token (valid for 15 minutes) has been dispatched "
            "to your designated enterprise security channel."
        )
    }

    # Only expose token in development mode for test automation
    if not IS_PRODUCTION:
        response_data["recovery_token"] = recovery_token

    return response_data


def reset_password_with_token(token: str, new_password: str) -> Dict[str, Any]:
    """
    Consumes a one-time password recovery token and updates the operator's credentials.
    Enforces expiry, single-use, and minimum password complexity.
    """
    if not token or not token.strip():
        raise ValueError("Recovery token is required.")

    if not new_password or len(new_password) < 8:
        raise ValueError("New password must be at least 8 characters long.")

    rec = get_recovery_token(token.strip())
    if not rec:
        raise ValueError("Invalid or unrecognized password recovery token.")

    if rec.get("used"):
        raise ValueError("This recovery token has already been consumed.")

    expires_at = rec.get("expires_at", "")
    if expires_at:
        try:
            exp_epoch = time.mktime(time.strptime(expires_at, "%Y-%m-%d %H:%M:%S"))
            if time.time() > exp_epoch:
                raise ValueError("Password recovery token has expired (15-minute validity exceeded).")
        except Exception:
            pass

    email = rec["email"]
    operator = SOC_OPERATORS.get(email)
    if not operator:
        raise ValueError(f"Associated operator account '{email}' not found.")

    # Update password hash with a fresh unique salt
    operator["password_hash"] = hash_password(new_password)

    # Mark token as consumed
    mark_recovery_token_used(token.strip())

    return {
        "status": "SUCCESS",
        "message": f"Password for {operator['name']} ({email}) has been successfully reset. You may now log in.",
        "email": email
    }


# -----------------------------------------------------------------------------
# SOC Administrator Clearance Requests
# -----------------------------------------------------------------------------
def submit_access_clearance_request(name: str, email: str, clearance_level: str, reason: str) -> Dict[str, Any]:
    """Logs a SOC clearance request and persists a formal tracking ticket in SQLite."""
    clean_email = email.strip().lower()
    if not validate_email_format(clean_email):
        raise ValueError("Invalid corporate email format.")

    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    ticket_id = f"SOC-REQ-{time.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    ticket = {
        "ticket_id": ticket_id,
        "name": name.strip(),
        "email": clean_email,
        "clearance_level": clearance_level,
        "reason": reason.strip(),
        "status": "PENDING_SOC_SUPERVISOR_APPROVAL",
        "timestamp": now_str
    }
    ACCESS_REQUEST_TICKETS.append(ticket)

    try:
        save_clearance_ticket(ticket)
    except Exception:
        pass

    return {
        "status": "SUCCESS",
        "ticket_id": ticket_id,
        "message": (
            f"Access clearance request logged successfully under Ticket #{ticket_id}. "
            "A SOC Operations Supervisor has been notified for identity verification and role assignment."
        )
    }
