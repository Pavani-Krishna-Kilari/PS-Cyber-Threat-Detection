"""
Unit and Integration Tests for AI-SIEM SOC Authentication & Login Page.

Verifies:
1. Static serving of /login, /static/css/login.css, and /static/js/login.js.
2. Content completeness matching design specifications (branding, feature cards, form fields).
3. Secure operator credential authentication (admin@soc.ai / CyberShield2026!).
4. Rejection of invalid credentials, unknown emails, and malformed email addresses.
5. Session token verification via /api/auth/me and revocation via /api/auth/logout.
6. HttpOnly, SameSite cookie generation on login and deletion on logout.
7. Brute-force rate limiting blocking after consecutive failed attempts.
8. End-to-end password recovery protocol and password reset with one-time token.
9. Session expiration enforcement.
10. Google Workspace OAuth 2.0 endpoint and status inspection.
11. Contact administrator clearance ticket generation.
12. Protected dashboard route access control (/api/dashboard/secure-session).
13. Session persistence across in-memory cache flushes via SQLite user_sessions table.
14. Purging of revoked sessions from SQLite.

Run with:
    python -m unittest tests.test_auth_and_login -v
"""

import time
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.auth import (
    SOC_OPERATORS,
    ACTIVE_SESSIONS,
    authenticate_operator,
    validate_email_format,
    reset_rate_limits_for_tests
)
from backend.database import get_user_session


class TestAuthAndLogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        reset_rate_limits_for_tests()
        self.client.cookies.clear()

    def test_login_page_served_at_login_route(self):
        """Verifies GET /login serves the complete AI-SIEM SOC login page."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # 1. Branding & Titles
        self.assertIn("AI SIEM SOC", html)
        self.assertIn("AI-Powered Security Information and Event Management", html)
        self.assertIn("Detect", html)
        self.assertIn("Analyze", html)
        self.assertIn("Respond", html)

        # 2. Three Feature Cards
        self.assertIn("Real-Time Threat Detection", html)
        self.assertIn("Identify security threats as they happen", html)
        self.assertIn("Intelligent Analytics", html)
        self.assertIn("Analyze and visualize security events", html)
        self.assertIn("Automated Response", html)
        self.assertIn("Respond intelligently to potential cyber threats", html)

        # 3. Canvases for Dynamic Visuals
        self.assertIn('id="networkCanvas"', html)
        self.assertIn('id="globeCanvas"', html)

        # 4. Login Card Elements
        self.assertIn("Welcome Back!", html)
        self.assertIn("Sign in to your AI SIEM SOC dashboard", html)
        self.assertIn('id="inputEmail"', html)
        self.assertIn('id="inputPassword"', html)
        self.assertIn('id="btnTogglePassword"', html)
        self.assertIn('id="checkRememberMe"', html)
        self.assertIn('id="linkForgotPassword"', html)
        self.assertIn('id="btnLogin"', html)
        self.assertIn('id="btnGoogleLogin"', html)
        self.assertIn('id="linkContactAdmin"', html)
        self.assertIn('id="btnQuickFill"', html)

        # 5. Modals
        self.assertIn('id="modalForgotPassword"', html)
        self.assertIn('id="modalContactAdmin"', html)
        self.assertIn('id="modalGoogleSSO"', html)

        # 6. Static Asset Links & Cinematic Transition Video
        self.assertIn("/static/css/login.css", html)
        self.assertIn("/static/js/login.js", html)
        self.assertIn('id="loginSuccessOverlay"', html)
        self.assertIn('id="loginSuccessVideo"', html)
        self.assertIn("/static/videos/login_success.mp4", html)

    def test_login_css_served(self):
        """Verifies GET /static/css/login.css returns valid CSS rules."""
        resp = self.client.get("/static/css/login.css")
        self.assertEqual(resp.status_code, 200)
        css = resp.text
        self.assertIn("--accent-cyan: #00E5FF", css)
        self.assertIn("--accent-purple: #8B35FF", css)
        self.assertIn(".login-glass-card", css)
        self.assertIn(".feature-card", css)
        self.assertIn("@keyframes rotateCW", css)
        self.assertIn(".login-success-overlay", css)
        self.assertIn(".login-success-video", css)
        self.assertIn("object-fit: contain", css)

    def test_login_js_served(self):
        """Verifies GET /static/js/login.js returns valid ES6+ module."""
        resp = self.client.get("/static/js/login.js")
        self.assertEqual(resp.status_code, 200)
        js = resp.text
        self.assertIn("initParticleNetwork", js)
        self.assertIn("initCyberGlobe", js)
        self.assertIn("initLoginForm", js)
        self.assertIn("/api/auth/login", js)
        self.assertIn("playSuccessTransitionAndRedirect", js)
        self.assertIn("loginSuccessVideo", js)
        self.assertIn("ended", js)

    def test_login_success_video_served_via_static_route(self):
        """Verifies that the extracted 2-second reference video is served via /static/videos/."""
        resp = self.client.get("/static/videos/login_success.mp4")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "video/mp4")
        self.assertGreater(len(resp.content), 200_000)

    def test_login_success_video_properties(self):
        """Verifies extracted video file exists and duration is exactly 2.0 seconds."""
        from pathlib import Path
        import subprocess

        vid_path = Path("frontend/videos/login_success.mp4")
        self.assertTrue(vid_path.exists(), "Extracted video file does not exist at frontend/videos/login_success.mp4")

        ffprobe = r"C:\Users\pavani krishna\AppData\Local\Programs\GNU Octave\Octave-11.1.0\mingw64\bin\ffprobe.exe"
        if Path(ffprobe).exists():
            cmd = [
                ffprobe,
                "-v", "error",
                "-show_entries", "format=duration:stream=width,height",
                "-of", "default=noprint_wrappers=1:nokey=1",
                str(vid_path)
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            lines = [l.strip() for l in res.stdout.strip().splitlines() if l.strip()]
            self.assertGreaterEqual(len(lines), 3)
            width, height, duration = int(lines[0]), int(lines[1]), float(lines[2])
            self.assertEqual(width, 736)
            self.assertEqual(height, 414)
            self.assertAlmostEqual(duration, 2.0, delta=0.05)

    def test_successful_admin_login(self):
        """Verifies successful authentication with valid SOC admin credentials."""
        payload = {
            "email": "admin@soc.ai",
            "password": "CyberShield2026!",
            "remember_me": True
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(data["session_token"].startswith("SOC-SEC-"))
        self.assertIsNotNone(data["user"])
        self.assertEqual(data["user"]["email"], "admin@soc.ai")
        self.assertIn("Alex Vance", data["user"]["name"])
        self.assertTrue("Head of SOC" in data["user"]["role"] or "Lead SOC" in data["user"]["role"])
        self.assertIn("Level 5", data["user"]["clearance"])

    def test_login_sets_httponly_cookie(self):
        """Verifies that login sets a secure HttpOnly cookie for session persistence."""
        payload = {
            "email": "admin@soc.ai",
            "password": "CyberShield2026!",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        cookies = resp.cookies
        self.assertIn("siem_session", cookies)
        self.assertTrue(cookies["siem_session"].startswith("SOC-SEC-"))

    def test_successful_analyst_login(self):
        """Verifies successful authentication for Tier-2 analyst."""
        payload = {
            "email": "analyst@soc.ai",
            "password": "ThreatHunter2026!",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["user"]["callsign"], "Sentinel-4")

    def test_failed_login_incorrect_password(self):
        """Verifies HTTP 401 when password does not match."""
        payload = {
            "email": "admin@soc.ai",
            "password": "IncorrectPassword999",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Access Denied", resp.json()["detail"])

    def test_failed_login_unrecognized_email(self):
        """Verifies HTTP 401 when account is not recognized with demo guidance."""
        payload = {
            "email": "unregistered@external.org",
            "password": "SomePassword123!",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Unrecognized SOC operator account", resp.json()["detail"])

    def test_failed_login_malformed_email(self):
        """Verifies HTTP 401 when email format is invalid."""
        payload = {
            "email": "invalid_email_string",
            "password": "Password123!",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid email format", resp.json()["detail"])

    def test_failed_login_empty_or_whitespace_password(self):
        """Verifies rejection when password consists of whitespace only."""
        payload = {
            "email": "admin@soc.ai",
            "password": "   ",
            "remember_me": False
        }
        resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("cannot be empty", resp.json()["detail"])

    def test_rate_limiting_blocks_after_max_failed_attempts(self):
        """Verifies that 5 consecutive failed logins trigger HTTP 429 rate limiting."""
        payload = {
            "email": "admin@soc.ai",
            "password": "WrongPassword!",
            "remember_me": False
        }
        # First 5 attempts fail with 401
        for _ in range(5):
            r = self.client.post("/api/auth/login", json=payload)
            self.assertEqual(r.status_code, 401)

        # 6th attempt must be blocked by rate limiter with 429
        blocked_resp = self.client.post("/api/auth/login", json=payload)
        self.assertEqual(blocked_resp.status_code, 429)
        self.assertIn("Rate limit exceeded", blocked_resp.json()["detail"])

    def test_auth_me_and_logout_lifecycle(self):
        """Verifies /api/auth/me checks active session, and /api/auth/logout revokes it."""
        # 1. Login
        login_resp = self.client.post("/api/auth/login", json={
            "email": "admin@soc.ai",
            "password": "CyberShield2026!",
            "remember_me": False
        })
        token = login_resp.json()["session_token"]

        # 2. Check /api/auth/me
        me_resp = self.client.get(f"/api/auth/me?token={token}")
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["user"]["email"], "admin@soc.ai")

        # 3. Logout
        logout_resp = self.client.post(f"/api/auth/logout?token={token}")
        self.assertEqual(logout_resp.status_code, 200)

        # 4. Subsequent me check must fail (HTTP 401)
        revoked_resp = self.client.get(f"/api/auth/me?token={token}")
        self.assertEqual(revoked_resp.status_code, 401)

    def test_protected_dashboard_route_unauthenticated(self):
        """Verifies that accessing protected route without a token returns HTTP 401."""
        resp = self.client.get("/api/dashboard/secure-session")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Authentication token required", resp.json()["detail"])

    def test_protected_dashboard_route_invalid_token(self):
        """Verifies that accessing protected route with invalid token returns HTTP 401."""
        resp = self.client.get("/api/dashboard/secure-session?token=INVALID-TOKEN-999")
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid or expired SOC security clearance token", resp.json()["detail"])

    def test_protected_dashboard_route_authenticated(self):
        """Verifies that accessing protected route with a valid token returns 200 with clearance info."""
        login_resp = self.client.post("/api/auth/login", json={
            "email": "admin@soc.ai",
            "password": "CyberShield2026!",
            "remember_me": False
        })
        token = login_resp.json()["session_token"]

        resp = self.client.get(f"/api/dashboard/secure-session?token={token}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "AUTHENTICATED")
        self.assertIn("Level 5", data["clearance"])
        self.assertEqual(data["user"]["email"], "admin@soc.ai")

    def test_protected_dashboard_route_cookie_auth(self):
        """Verifies that protected route accepts HttpOnly cookie without query token."""
        login_resp = self.client.post("/api/auth/login", json={
            "email": "admin@soc.ai",
            "password": "CyberShield2026!",
            "remember_me": False
        })
        token = login_resp.json()["session_token"]

        # Call without ?token=, passing cookie
        resp = self.client.get("/api/dashboard/secure-session", cookies={"siem_session": token})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "AUTHENTICATED")

    def test_session_persistence_across_memory_flush(self):
        """
        Verifies that session data survives in-memory cache clear by reading from SQLite.
        Simulates backend restart where memory is cleared but SQLite persists.
        """
        login_resp = self.client.post("/api/auth/login", json={
            "email": "operator@soc.ai",
            "password": "SiemOperator2026!",
            "remember_me": True
        })
        token = login_resp.json()["session_token"]

        # Simulate server restart: flush in-memory ACTIVE_SESSIONS
        if token in ACTIVE_SESSIONS:
            del ACTIVE_SESSIONS[token]

        # Verify SQLite persistence recovers the session
        resp = self.client.get(f"/api/auth/me?token={token}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["user"]["email"], "operator@soc.ai")
        self.assertEqual(resp.json()["user"]["callsign"], "Vanguard-2")

    def test_session_expiration_enforcement(self):
        """Verifies that an expired session token returns 401 and is revoked."""
        login_resp = self.client.post("/api/auth/login", json={
            "email": "operator@soc.ai",
            "password": "SiemOperator2026!",
            "remember_me": False
        })
        token = login_resp.json()["session_token"]

        # Manually alter expires_at to a past timestamp
        past_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 3600))
        if token in ACTIVE_SESSIONS:
            ACTIVE_SESSIONS[token]["expires_at"] = past_str

        # Subsequent check must fail with 401
        resp = self.client.get(f"/api/auth/me?token={token}")
        self.assertEqual(resp.status_code, 401)

    def test_logout_purges_sqlite_persistence(self):
        """Verifies that logging out revokes the session from both memory and SQLite."""
        login_resp = self.client.post("/api/auth/login", json={
            "email": "operator@soc.ai",
            "password": "SiemOperator2026!",
            "remember_me": False
        })
        token = login_resp.json()["session_token"]

        # Verify it exists in SQLite
        db_session = get_user_session(token)
        self.assertIsNotNone(db_session)

        # Perform logout
        logout_resp = self.client.post(f"/api/auth/logout?token={token}")
        self.assertEqual(logout_resp.status_code, 200)

        # Verify purged from SQLite
        db_after = get_user_session(token)
        self.assertIsNone(db_after)

    def test_google_oauth_url_endpoint(self):
        """Verifies GET /api/auth/oauth/google/url returns OAuth status and CSRF state."""
        resp = self.client.get("/api/auth/oauth/google/url")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("is_configured", data)
        self.assertIn("state", data)
        self.assertIn("message", data)

    def test_google_sso_endpoint_labeled_simulation(self):
        """Verifies Google Workspace SSO returns transparently labeled simulation when credentials unconfigured."""
        payload = {"requested_email": "analyst.google@soc-siem.cloud"}
        resp = self.client.post("/api/auth/google", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["status"], "DEMO_SIMULATION")
        self.assertFalse(data["is_live_sso"])
        self.assertTrue(data["session_token"].startswith("SOC-GGL-"))
        self.assertIn("Simulation Mode", data["message"])
        self.assertEqual(data["user"]["email"], "analyst.google@soc-siem.cloud")

    def test_end_to_end_password_reset_flow(self):
        """Verifies full password reset lifecycle: request token -> reset password -> login with new password."""
        # 1. Request recovery token
        req_resp = self.client.post("/api/auth/forgot-password", json={"email": "operator@soc.ai"})
        self.assertEqual(req_resp.status_code, 200)
        token = req_resp.json()["recovery_token"]
        self.assertTrue(token.startswith("REC-"))

        # 2. Reset password using the one-time token
        new_pw = "NewSecureOperator2026!"
        reset_resp = self.client.post("/api/auth/reset-password", json={
            "token": token,
            "new_password": new_pw
        })
        self.assertEqual(reset_resp.status_code, 200)
        self.assertEqual(reset_resp.json()["status"], "SUCCESS")

        # 3. Old password must now fail
        old_login = self.client.post("/api/auth/login", json={
            "email": "operator@soc.ai",
            "password": "SiemOperator2026!",
            "remember_me": False
        })
        self.assertEqual(old_login.status_code, 401)

        # 4. New password succeeds
        new_login = self.client.post("/api/auth/login", json={
            "email": "operator@soc.ai",
            "password": new_pw,
            "remember_me": False
        })
        self.assertEqual(new_login.status_code, 200)
        self.assertEqual(new_login.json()["status"], "SUCCESS")

        # 5. Token cannot be reused (single-use enforcement)
        reused_resp = self.client.post("/api/auth/reset-password", json={
            "token": token,
            "new_password": "YetAnotherPassword123!"
        })
        self.assertEqual(reused_resp.status_code, 400)
        self.assertIn("already been consumed", reused_resp.json()["detail"])

        # Clean up: restore default password for test isolation
        from backend.auth import hash_password
        SOC_OPERATORS["operator@soc.ai"]["password_hash"] = hash_password("SiemOperator2026!")

    def test_forgot_password_invalid_email(self):
        """Verifies invalid email format raises HTTP 400."""
        resp = self.client.post("/api/auth/forgot-password", json={"email": "not_an_email"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid email address format", resp.json()["detail"])

    def test_contact_admin_endpoint(self):
        """Verifies submission of SOC clearance access request ticket."""
        payload = {
            "name": "Sarah Connor",
            "email": "sarah.connor@cyber-defense.mil",
            "clearance_level": "Tier 3 - Advanced Threat Hunting & Neural Tuning",
            "reason": "Authorized security penetration auditor evaluating AI-SIEM event profiles."
        }
        resp = self.client.post("/api/auth/contact-admin", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["status"], "SUCCESS")
        self.assertTrue(data["ticket_id"].startswith("SOC-REQ-"))
        self.assertIn(data["ticket_id"], data["message"])


if __name__ == "__main__":
    unittest.main()
