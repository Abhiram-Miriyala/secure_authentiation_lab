"""
Database Layer for Secure Authentication Lab.

Demonstrates secure database interactions using SQLite and parameterized queries.
All SQL operations strictly use parameter binding ('?') to ensure SQL injection
attempts are safely neutralized at the database driver level.
"""

import sqlite3
import os
from flask import current_app, g


def get_db():
    """
    Retrieve or initialize the SQLite database connection for the current application context.
    
    Uses row_factory = sqlite3.Row for dictionary-like column access.
    """
    if "db" not in g:
        db_path = current_app.config["DATABASE"]
        
        # Ensure directory exists for persistent SQLite database files
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        # Enable Foreign Key enforcement in SQLite
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app=None):
    """Initialize database tables schema."""
    if app:
        with app.app_context():
            _create_schema()
    else:
        _create_schema()


def _create_schema():
    """Execute DDL statements to set up secure schema."""
    db = get_db()
    cursor = db.cursor()

    # User Accounts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
    """)

    # Audit Logging Table (Records security events without sensitive credentials)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            status TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    db.commit()


# ==============================================================================
# PARAMETERIZED DATA ACCESS METHODS (IMMUNE TO SQL INJECTION)
# ==============================================================================

def create_user(username: str, password_hash: str) -> int | None:
    """
    Create a new user account with parameterized SQL.

    Args:
        username: Cleaned, validated username.
        password_hash: Argon2id hash string.

    Returns:
        New user ID if successful, or None if duplicate username.
    """
    db = get_db()
    try:
        cursor = db.cursor()
        # Parameterized query with '?' placeholders
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?);",
            (username.strip(), password_hash),
        )
        db.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        # Username uniqueness constraint violation
        db.rollback()
        return None


def get_user_by_username(username: str) -> sqlite3.Row | None:
    """
    Query a user record by username using parameterized SQL.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, created_at, last_login FROM users WHERE username = ?;",
        (username.strip(),),
    )
    return cursor.fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    """
    Query a user record by primary key ID using parameterized SQL.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, created_at, last_login FROM users WHERE id = ?;",
        (user_id,),
    )
    return cursor.fetchone()


def update_last_login(user_id: int) -> None:
    """
    Update the last_login timestamp for a user.
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?;",
        (user_id,),
    )
    db.commit()


def log_audit_event(username: str, ip_address: str, status: str) -> None:
    """
    Log an authentication event for intrusion detection and security audits.
    Never logs raw passwords or confidential token data.
    """
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO login_audit (username, ip_address, status) VALUES (?, ?, ?);",
            (username[:50] if username else "UNKNOWN", ip_address[:45], status),
        )
        db.commit()
    except Exception:
        # Prevent audit logging failure from breaking core app flow
        pass
