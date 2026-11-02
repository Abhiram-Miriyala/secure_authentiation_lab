"""
Pytest Fixtures and Test Configuration for Secure Authentication Lab.

Configures an isolated testing environment with an in-memory SQLite database
and test client fixtures.
"""

import os
import tempfile
import pytest
from app import create_app
from app.config import TestingConfig
from app.models import init_db, create_user
from app.security import hash_password


@pytest.fixture
def app():
    """
    Create and configure a fresh Flask application instance for each test.
    Uses an isolated temporary database file to avoid cross-test contamination.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db")

    class TestAppConfig(TestingConfig):
        DATABASE = db_path
        WTF_CSRF_ENABLED = False  # Disabled for unit tests to test business logic directly
        TESTING = True
        RATELIMIT_ENABLED = True
        RATELIMIT_STORAGE_URI = "memory://"

    app = create_app(TestAppConfig)

    with app.app_context():
        init_db(app)

    yield app

    # Cleanup temporary database
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def client(app):
    """A test client for the application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner for the application."""
    return app.test_cli_runner()


@pytest.fixture
def test_user(app):
    """
    Pre-populates a valid test user in the database.
    Username: 'valid_analyst'
    Password: 'CorrectPassword2026!#'
    """
    username = "valid_analyst"
    password = "CorrectPassword2026!#"
    with app.app_context():
        hashed = hash_password(password)
        user_id = create_user(username, hashed)
        return {
            "id": user_id,
            "username": username,
            "password": password,
            "hash": hashed,
        }
