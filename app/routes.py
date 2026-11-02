"""
Application Routes and Blueprints for Secure Authentication Lab.

Defines:
- main_bp: Landing page, authenticated dashboard, and security architecture documentation
- auth_bp: Registration, login (rate-limited, generic errors), and session termination
"""

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
)
from app import limiter
from app.auth import login_required, establish_session, terminate_session, get_current_user
from app.models import (
    create_user,
    get_user_by_username,
    log_audit_event,
)
from app.security import (
    hash_password,
    verify_password,
    dummy_verify,
    validate_username,
    validate_password,
    GENERIC_LOGIN_ERROR,
)

main_bp = Blueprint("main", __name__)
auth_bp = Blueprint("auth", __name__)


# ==============================================================================
# MAIN BLUEPRINT (Informational & Authenticated Views)
# ==============================================================================

@main_bp.route("/")
def index():
    """Public landing page presenting the Secure Authentication Lab architecture."""
    return render_template("index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """
    Authenticated User Dashboard.
    
    Protected by @login_required decorator.
    Only accessible with an active, unexpired session cookie.
    """
    user = get_current_user()
    if not user:
        # If user record disappeared from database, revoke session
        terminate_session()
        flash("Session invalid. Please log in again.", "warning")
        return redirect(url_for("auth.login"))

    session_details = {
        "username": session.get("username"),
        "login_time": session.get("login_time"),
        "last_active": session.get("last_active"),
        "cookie_httponly": current_app.config.get("SESSION_COOKIE_HTTPONLY"),
        "cookie_samesite": current_app.config.get("SESSION_COOKIE_SAMESITE"),
        "cookie_secure": current_app.config.get("SESSION_COOKIE_SECURE"),
        "session_lifetime": current_app.config.get("PERMANENT_SESSION_LIFETIME"),
    }

    return render_template("dashboard.html", user=user, session_details=session_details)


@main_bp.route("/security")
def security_info():
    """
    Security Architecture and Controls Breakdown.
    
    Provides deep-dive explanations of Argon2id, timing attack mitigations,
    session security, CSRF protection, and rate limiting controls.
    """
    return render_template("security.html")


# ==============================================================================
# AUTHENTICATION BLUEPRINT (Registration, Login, Logout)
# ==============================================================================

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    User Registration Endpoint.
    
    Defensive controls applied:
    1. Server-side username validation (length, regex character whitelist)
    2. Server-side password complexity and length enforcement (12-128 chars, upper/lower/digit/special)
    3. Duplicate username prevention (checks DB and handles UNIQUE constraint)
    4. Argon2id password hashing (no plaintext stored)
    5. CSRF token verification (enforced by Flask-WTF)
    """
    # If user is already authenticated, redirect to dashboard
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Server-side Username Validation
        valid_u, user_err = validate_username(username)
        if not valid_u:
            flash(user_err, "danger")
            return render_template("register.html", username=username), 400

        # 2. Server-side Password Validation
        valid_p, pass_err = validate_password(password)
        if not valid_p:
            flash(pass_err, "danger")
            return render_template("register.html", username=username), 400

        # 3. Password Confirmation Match
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username), 400

        # 4. Check for Duplicate Username
        existing_user = get_user_by_username(username)
        if existing_user is not None:
            flash("Username is already taken. Please choose a different username.", "danger")
            return render_template("register.html"), 400

        # 5. Compute Argon2id Hash
        hashed_password = hash_password(password)

        # 6. Parameterized Database Insertion
        new_user_id = create_user(username, hashed_password)
        if not new_user_id:
            flash("An error occurred during account creation. Please try again.", "danger")
            return render_template("register.html"), 500

        # Audit Log Event
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        log_audit_event(username, client_ip, "REGISTRATION_SUCCESS")

        flash("Account created successfully! Please log in with your credentials.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """
    User Login Endpoint.
    
    Defensive controls applied:
    1. Rate Limiting: 5 attempts per minute per IP address
    2. Server-side Input Validation: sanitizes and bounded lengths
    3. Parameterized SQL Query: prevents SQL injection
    4. Generic Authentication Errors: identical message and 401 code
    5. Timing Attack Mitigation: dummy hash verification for non-existent users
    6. Session Fixation Defense: session.clear() and fresh token generation
    """
    # If user is already authenticated, redirect to dashboard
    if session.get("user_id"):
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

        # Input bounding and presence check
        if not username or not password or len(username) > 50 or len(password) > 256:
            # Execute dummy verify to keep timing constant even on malformed inputs
            dummy_verify("MalformedInputTimingPadding123!")
            log_audit_event(username[:30], client_ip, "LOGIN_FAILED_MALFORMED")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html", username=username[:50]), 401

        # Parameterized query to locate user
        user = get_user_by_username(username)

        # Non-existent user scenario: Perform dummy verification to prevent timing attack enumeration
        if user is None:
            dummy_verify(password)
            log_audit_event(username, client_ip, "LOGIN_FAILED_UNKNOWN_USER")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html", username=username), 401

        # Real user scenario: Cryptographically verify password against Argon2id hash
        if not verify_password(user["password_hash"], password):
            log_audit_event(username, client_ip, "LOGIN_FAILED_INVALID_PASSWORD")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html", username=username), 401

        # Authentication Successful: Establish secure session
        establish_session(user)
        log_audit_event(username, client_ip, "LOGIN_SUCCESS")

        flash(f"Welcome back, {user['username']}! Authentication successful.", "success")

        # Validate redirect target against Open Redirect attacks
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("main.dashboard"))

    return render_template("login.html")


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Session Termination Endpoint.
    
    Destroys active session keys and clears cookie data.
    """
    terminate_session()
    flash("You have been securely logged out. Session terminated.", "info")
    return redirect(url_for("auth.login"))
