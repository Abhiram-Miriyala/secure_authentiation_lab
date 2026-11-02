"""
Configuration Module for Secure Authentication Lab.

Defines environment-driven configurations for development, testing,
and production environments adhering to defensive cybersecurity principles.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env if present
basedir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(os.path.join(basedir, ".."))
load_dotenv(os.path.join(parent_dir, ".env"))


class Config:
    """Base application configuration."""

    # Cryptographic Secret Key for signing session cookies & CSRF tokens
    # Defaults to a known developmental fallback if not provided in environment
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "dev-insecure-key-change-in-production-a93f7c4e2b10984f826315c1e5482e9b"
    )

    # SQLite Database File Path
    INSTANCE_DIR = os.path.join(parent_dir, "instance")
    DATABASE = os.path.join(INSTANCE_DIR, "secure_auth.db")

    # Secure Session Cookie Defenses
    # HTTPOnly: Prevents client-side scripts (XSS attacks) from accessing session cookies
    SESSION_COOKIE_HTTPONLY = True

    # SameSite: 'Lax' protects against Cross-Site Request Forgery (CSRF) in cross-site navigations
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

    # Secure: Restricts cookie transmission to encrypted HTTPS connections only
    # Set to False during local HTTP development; set to True in production HTTPS
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "t")

    # Session Lifetime & Expiration (Default: 30 minutes of inactivity timeout)
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("PERMANENT_SESSION_LIFETIME_MINUTES", "30"))
    )

    # CSRF Protection via Flask-WTF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF token valid for 1 hour

    # Rate Limiting Backend Configuration
    # Uses in-memory storage for development and testing
    # In production, this should point to a Redis cluster, e.g., 'redis://localhost:6379/0'
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day; 50 per hour")
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_ENABLED = True


class TestingConfig(Config):
    """Configuration applied during automated Pytest execution."""

    TESTING = True
    # In-memory SQLite database ensures fast, isolated, non-persistent test runs
    DATABASE = ":memory:"
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = False  # Enabled selectively in tests if testing CSRF directly
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=2)  # Short lifetime for expiration tests
