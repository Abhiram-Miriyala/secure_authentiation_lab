"""
Automated Test Suite for Rate Limiting Controls.

Validates:
14. Login rate limiting (mitigates brute-force credential attacks via HTTP 429)
"""

import pytest
from app import limiter


def test_login_rate_limiting(client, app):
    """
    Test Case 14: Login rate limiting.
    Submits repeated rapid authentication requests to /login.
    Verifies that after 5 failed attempts within 1 minute, the 6th attempt
    is blocked with an HTTP 429 Too Many Requests status code.
    """
    with app.app_context():
        limiter.reset()

    test_ip = "192.168.1.100"

    # Attempts 1 through 5: Allowed through, return 401 (bad credentials)
    for i in range(1, 6):
        res = client.post(
            "/login",
            data={
                "username": f"brute_force_user_{i}",
                "password": "WrongPassword123!#",
            },
            environ_base={"REMOTE_ADDR": test_ip},
        )
        assert res.status_code == 401, f"Attempt {i} should return 401, got {res.status_code}"

    # 6th Attempt: Breaches the 5/minute threshold -> Must return HTTP 429 Too Many Requests
    blocked_res = client.post(
        "/login",
        data={
            "username": "brute_force_user_6",
            "password": "WrongPassword123!#",
        },
        environ_base={"REMOTE_ADDR": test_ip},
    )

    assert blocked_res.status_code == 429, (
        f"Expected 429 Too Many Requests on attempt 6, got {blocked_res.status_code}"
    )
    assert b"Rate Limit Exceeded" in blocked_res.data or b"Too Many Requests" in blocked_res.data
