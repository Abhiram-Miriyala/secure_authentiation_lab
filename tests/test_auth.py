"""
Automated Test Suite for Authentication Workflows.

Validates:
1. Successful user registration
2. Duplicate username rejection
5. Successful login
6. Incorrect password rejection
7. Nonexistent username rejection
8. Generic error message consistency
9. Unauthorized dashboard access
10. Successful logout
"""

import pytest
from app.models import get_user_by_username
from app.security import GENERIC_LOGIN_ERROR


def test_successful_registration(client, app):
    """
    Test Case 1: Successful user registration.
    Verifies that a valid registration request is accepted, redirects to login,
    and creates a new user record in the database.
    """
    response = client.post(
        "/register",
        data={
            "username": "sec_analyst_01",
            "password": "StrongPassword2026!#",
            "confirm_password": "StrongPassword2026!#",
        },
        follow_redirects=False,
    )

    # Must redirect to login page upon success
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    # Verify user exists in the database
    with app.app_context():
        user = get_user_by_username("sec_analyst_01")
        assert user is not None
        assert user["username"] == "sec_analyst_01"


def test_duplicate_username_rejection(client, test_user):
    """
    Test Case 2: Duplicate username rejection.
    Verifies that registering with an existing username is rejected with HTTP 400.
    """
    response = client.post(
        "/register",
        data={
            "username": test_user["username"],  # Duplicate
            "password": "DifferentPassword2026!#",
            "confirm_password": "DifferentPassword2026!#",
        },
        follow_redirects=True,
    )

    assert response.status_code == 400
    assert b"Username is already taken" in response.data


def test_successful_login(client, test_user):
    """
    Test Case 5: Successful login.
    Verifies that valid credentials authenticate, establish a session,
    and redirect to the dashboard.
    """
    response = client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")

    # Verify session variables are populated
    with client.session_transaction() as sess:
        assert sess.get("user_id") == test_user["id"]
        assert sess.get("username") == test_user["username"]
        assert sess.get("session_token") is not None

    # Follow redirect to dashboard
    dashboard_res = client.get("/dashboard")
    assert dashboard_res.status_code == 200
    assert test_user["username"].encode() in dashboard_res.data


def test_incorrect_password_rejection(client, test_user):
    """
    Test Case 6: Incorrect password rejection.
    Verifies that an incorrect password for a valid username is rejected with HTTP 401.
    """
    response = client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": "WrongPassword2026!#",
        },
        follow_redirects=True,
    )

    assert response.status_code == 401
    assert GENERIC_LOGIN_ERROR.encode() in response.data

    # Ensure no authenticated session was granted
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_nonexistent_username_rejection(client):
    """
    Test Case 7: Nonexistent username rejection.
    Verifies that authenticating with an unknown username is rejected with HTTP 401.
    """
    response = client.post(
        "/login",
        data={
            "username": "ghost_user_999",
            "password": "AnyPassword123!#",
        },
        follow_redirects=True,
    )

    assert response.status_code == 401
    assert GENERIC_LOGIN_ERROR.encode() in response.data

    with client.session_transaction() as sess:
        assert sess.get("user_id") is None


def test_generic_error_message_consistency(client, test_user):
    """
    Test Case 8: Generic error message consistency.
    Verifies that error messages returned for non-existent users and incorrect
    passwords are 100% identical in text and status code, defeating user enumeration.
    """
    # 1. Non-existent username
    res_nonexistent = client.post(
        "/login",
        data={
            "username": "unknown_user_x",
            "password": "SomePassword123!#",
        },
    )

    # 2. Existing username with bad password
    res_bad_pw = client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": "IncorrectPassword123!#",
        },
    )

    # Both must return 401 Unauthorized
    assert res_nonexistent.status_code == 401
    assert res_bad_pw.status_code == 401

    # Both must contain the identical generic error message
    assert GENERIC_LOGIN_ERROR.encode() in res_nonexistent.data
    assert GENERIC_LOGIN_ERROR.encode() in res_bad_pw.data


def test_unauthorized_dashboard_access(client):
    """
    Test Case 9: Unauthorized dashboard access.
    Verifies that accessing /dashboard without authentication redirects to /login.
    """
    response = client.get("/dashboard", follow_redirects=False)

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    # When following the redirect, verify security flash alert is present
    redirected = client.get("/dashboard", follow_redirects=True)
    assert b"Authentication required" in redirected.data


def test_successful_logout(client, test_user):
    """
    Test Case 10: Successful logout.
    Verifies that logging out invalidates session state and blocks subsequent dashboard access.
    """
    # Authenticate user
    client.post(
        "/login",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
        },
    )

    # Verify active session
    with client.session_transaction() as sess:
        assert sess.get("user_id") is not None

    # Execute logout
    logout_res = client.post("/logout", follow_redirects=True)
    assert logout_res.status_code == 200
    assert b"logged out" in logout_res.data

    # Verify session is wiped
    with client.session_transaction() as sess:
        assert sess.get("user_id") is None

    # Verify dashboard cannot be accessed anymore
    dashboard_res = client.get("/dashboard", follow_redirects=False)
    assert dashboard_res.status_code == 302
    assert "/login" in dashboard_res.headers["Location"]
