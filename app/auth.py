"""
Authentication and Session Security Module for Secure Authentication Lab.

Provides:
1. Custom @login_required decorator with inactivity session timeout enforcement
2. Secure session generation with session fixation countermeasures
3. Invalidation and session clearing for secure logout
"""

import functools
import secrets
from datetime import datetime, timezone
from flask import session, redirect, url_for, flash, request, current_app
from app.models import get_user_by_id, update_last_login


def login_required(view):
    """
    Decorator to protect views against unauthorized access.
    
    Security controls:
    1. Verifies the existence of an active user session ('user_id' in session)
    2. Validates session freshness and enforces server-side inactivity timeout
    3. Invalidates stale sessions and redirects to the login page
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get("user_id")
        last_active = session.get("last_active")

        if user_id is None:
            flash("Authentication required. Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))

        # Check session inactivity expiration
        now_ts = datetime.now(timezone.utc).timestamp()
        timeout_seconds = current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds()

        if last_active and (now_ts - last_active > timeout_seconds):
            # Session expired: clean up and invalidate
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

        # Sliding session window: update activity timestamp
        session["last_active"] = now_ts
        return view(**kwargs)

    return wrapped_view


def establish_session(user: dict | object) -> None:
    """
    Establish a cryptographically secured user session.

    Defense against Session Fixation:
    By clearing the existing session dict completely before attaching authenticated
    credentials, any pre-authentication session identifiers or attributes established
    by an attacker are discarded. A new cryptographically random session token is issued.
    """
    # 1. Neutralize Session Fixation by clearing any pre-existing session state
    session.clear()

    # 2. Configure session persistence according to configuration lifetime
    session.permanent = True

    # 3. Populate authenticated identity and random anti-fixation token
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["session_token"] = secrets.token_hex(32)
    session["last_active"] = datetime.now(timezone.utc).timestamp()
    session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 4. Update persistent database audit timestamp
    update_last_login(user["id"])


def terminate_session() -> None:
    """
    Safely invalidate the user's session during logout.
    Removes all stored session keys and regenerates the session state.
    """
    session.clear()


def get_current_user():
    """
    Fetch the currently authenticated user record from the database, or None.
    """
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_user_by_id(user_id)
