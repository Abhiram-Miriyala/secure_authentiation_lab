"""
Automated Test Suite for Defensive Security Controls.

Validates:
3. Password hashing verification (Argon2id format and cryptographic strength)
4. Confirmation that plaintext passwords are not stored in database
11. Session expiration and inactivity timeout enforcement
12. Secure cookie configuration (HttpOnly, SameSite, Secure flags)
13. Server-side input validation (whitelisting, length boundaries, complexity criteria)
15. SQL injection resistance (parameterized queries withstand hostile payloads)
"""

import time
import pytest
from app import create_app
from app.config import TestingConfig
from app.models import get_db, init_db
from app.security import (
    hash_password,
    verify_password,
    validate_username,
    validate_password,
    GENERIC_LOGIN_ERROR,
)


def test_password_hashing_verification():
    """
    Test Case 3: Password hashing verification.
    Verifies that generated hashes strictly use the Argon2id algorithm,
    contain standard PHC formatted parameters (m=65536, t=3, p=4),
    and correctly verify identical versus non-identical passwords.
    """
    raw_password = "DefensiveP@ssword2026!"
    hashed = hash_password(raw_password)

    # Verify standard Argon2id PHC prefix
    assert hashed.startswith("$argon2id$")
    assert "m=65536" in hashed
    assert "t=3" in hashed
    assert "p=4" in hashed

    # Verify cryptographic matching
    assert verify_password(hashed, raw_password) is True
    assert verify_password(hashed, "IncorrectGuess123!") is False


def test_no_plaintext_passwords_stored(client, app):
    """
    Test Case 4: Confirmation that plaintext passwords are not stored.
    Performs raw database inspection on the SQLite user record to ensure the
    plaintext password does not appear in any column or unencrypted storage.
    """
    plaintext_password = "SuperSecretPlaintextP@ss2026!"
    username = "audit_target_user"

    # Register the user
    client.post(
        "/register",
        data={
            "username": username,
            "password": plaintext_password,
            "confirm_password": plaintext_password,
        },
    )

    # Inspect the raw database records directly
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
        row = cursor.fetchone()

        assert row is not None
        # Convert row values to string representations
        row_values = [str(col) for col in row]

        # Plaintext password must NOT exist anywhere in the record
        for val in row_values:
            assert plaintext_password not in val

        # Password hash column must be an Argon2id string
        stored_hash = row["password_hash"]
        assert stored_hash.startswith("$argon2id$")
        assert verify_password(stored_hash, plaintext_password) is True


def test_session_expiration(client, test_user):
    """
    Test Case 11: Session expiration.
    Simulates session timeout by backdating the last_active timestamp,
    verifying that the session is invalidated and access is denied.
    """
    # Authenticate successfully
    client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
        },
    )

    # Access dashboard while fresh
    res_fresh = client.get("/dashboard")
    assert res_fresh.status_code == 200

    # Backdate the session's last_active timestamp by 2 hours (7200 seconds)
    with client.session_transaction() as sess:
        sess["last_active"] = time.time() - 7200

    # Next request must detect expired inactivity window
    res_expired = client.get("/dashboard", follow_redirects=False)
    assert res_expired.status_code == 302
    assert "/login" in res_expired.headers["Location"]

    # Session must be completely purged
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_secure_cookie_configuration(client, test_user, app):
    """
    Test Case 12: Secure cookie configuration.
    Verifies that the session cookie is served with HttpOnly and SameSite=Lax flags.
    Also tests that Secure flag is enforced when HTTPS configuration is active.
    """
    # 1. Test Development Configuration (HttpOnly + SameSite)
    response = client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
        },
    )

    # Inspect Set-Cookie header
    cookie_header = response.headers.get("Set-Cookie", "")
    assert "session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header

    # 2. Test Production HTTPS Configuration (Secure=True)
    class SecureProdConfig(TestingConfig):
        SESSION_COOKIE_SECURE = True
        WTF_CSRF_ENABLED = False
        DATABASE = app.config["DATABASE"]

    secure_app = create_app(SecureProdConfig)
    secure_client = secure_app.test_client()
    secure_res = secure_client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        base_url="https://localhost",  # HTTPS protocol
    )
    secure_cookie = secure_res.headers.get("Set-Cookie", "")
    assert "Secure" in secure_cookie


def test_server_side_input_validation():
    """
    Test Case 13: Server-side input validation.
    Verifies defensive input rules for both usernames and passwords:
    - Whitelisting, length bounds, and complexity constraints.
    """
    # 1. Username Validation Testing
    # Valid usernames
    assert validate_username("alice")[0] is True
    assert validate_username("analyst_99")[0] is True

    # Invalid usernames
    assert validate_username("")[0] is False  # Empty
    assert validate_username("ab")[0] is False  # Too short (<3)
    assert validate_username("a" * 35)[0] is False  # Too long (>30)
    assert validate_username("user name")[0] is False  # Space
    assert validate_username("user<script>")[0] is False  # XSS probe
    assert validate_username("user;DROP TABLE")[0] is False  # SQL injection syntax

    # 2. Password Validation Testing
    # Valid password
    assert validate_password("ValidP@ssword2026!")[0] is True

    # Invalid passwords
    assert validate_password("")[0] is False  # Empty
    assert validate_password("Short1!Aa")[0] is False  # Too short (<12)
    assert validate_password("alllowercasepassword123!")[0] is False  # No uppercase
    assert validate_password("ALLUPPERCASEPASSWORD123!")[0] is False  # No lowercase
    assert validate_password("NoDigitsInPassword!@#A")[0] is False  # No digits
    assert validate_password("NoSpecialCharacters1234Aa")[0] is False  # No special char
    assert validate_password("A" * 150 + "1!a")[0] is False  # Too long (>128 chars, DoS mitigation)


def test_sql_injection_resistance(client, test_user, app):
    """
    Test Case 15: SQL injection resistance.
    Submits classic hostile SQL injection payloads in the username and password fields.
    Verifies that parameterized queries safely treat them as literal data, preventing
    authentication bypass and database manipulation.
    """
    malicious_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT null, 'hacked', 'hacked' --",
        "'; DROP TABLE users; --",
        "valid_analyst' OR 1=1 --",
    ]

    for idx, payload in enumerate(malicious_payloads):
        client_ip = f"10.10.1.{idx + 1}"

        # 1. Attempt injection in username field
        res_user_inj = client.post(
            "/login",
            data={
                "username": payload,
                "password": "Password123!#",
            },
            environ_base={"REMOTE_ADDR": client_ip},
        )
        assert res_user_inj.status_code == 401
        assert GENERIC_LOGIN_ERROR.encode() in res_user_inj.data

        # Ensure no session was granted
        with client.session_transaction() as sess:
            assert sess.get("user_id") is None

        # 2. Attempt injection in password field
        res_pass_inj = client.post(
            "/login",
            data={
                "username": test_user["username"],
                "password": payload,
            },
            environ_base={"REMOTE_ADDR": client_ip},
        )
        assert res_pass_inj.status_code == 401
        assert GENERIC_LOGIN_ERROR.encode() in res_pass_inj.data

        with client.session_transaction() as sess:
            assert sess.get("user_id") is None

    # Verify that the users table remains fully intact after DROP TABLE attempts
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT COUNT(*) FROM users;")
        count = cursor.fetchone()[0]
        assert count >= 1  # Table and records still exist!
