"""
Defensive Security Module for Secure Authentication Lab.

Implements core cryptographic and validation controls:
1. Argon2id Password Hashing (resistant to GPU/ASIC brute forcing and side-channel attacks)
2. Constant-Time Dummy Verification (neutralizes username enumeration via timing attacks)
3. Server-Side Input Validation (whitelisting, length bounds, complexity enforcement)
4. Generic Authentication Error Definitions
"""

import re
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# ==============================================================================
# 1. ARGON2ID PASSWORD HASHER CONFIGURATION
# ==============================================================================
# Argon2id is the winner of the Password Hashing Competition (PHC).
# It combines Argon2i (resistance to side-channel cache attacks) and
# Argon2d (resistance to GPU/ASIC hardware brute-force attacks).
#
# Parameters:
# - time_cost = 3 iterations
# - memory_cost = 65536 KiB (64 MiB RAM per hash calculation)
# - parallelism = 4 threads
# - hash_len = 32 bytes
# - type = Type.ID (Argon2id hybrid)
hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=argon2.Type.ID,
)

# Dummy hash used to equalize response timing when authenticating non-existent users.
# Precomputed once during initialization to avoid overhead.
DUMMY_HASH = hasher.hash("SecureAuthenticationLabDummyTimingMitigationPassword2026!")

# Standardized generic error message to prevent user enumeration
GENERIC_LOGIN_ERROR = "Invalid username or password."


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    Args:
        password: Raw user-supplied password string.

    Returns:
        Argon2id encoded hash string containing algorithm parameters, salt, and digest.
    """
    return hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Cryptographically verify a password against a stored Argon2id hash.

    Args:
        stored_hash: Argon2id hash string from database.
        password: Plaintext password attempt from user.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        return hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def dummy_verify(password: str) -> None:
    """
    Perform a dummy verification against a pre-generated hash.
    
    This ensures that when an attacker submits an unregistered username,
    the server consumes the exact same computational time (~64MB RAM and 3 iterations)
    as it would for a real user, neutralizing side-channel timing analysis.
    """
    try:
        hasher.verify(DUMMY_HASH, password)
    except (VerifyMismatchError, InvalidHashError):
        pass


def check_needs_rehash(stored_hash: str) -> bool:
    """
    Check if a stored hash needs upgrading due to modified security parameters.
    """
    return hasher.check_needs_rehash(stored_hash)


# ==============================================================================
# 2. SERVER-SIDE INPUT VALIDATION
# ==============================================================================
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
SPECIAL_CHARS_REGEX = re.compile(r'[!@#$%^&*(),.?":{}|<>\-_=+]')


def validate_username(username: str | None) -> tuple[bool, str | None]:
    """
    Validate username format, length, and character whitelist.

    Rules:
    - Must not be empty or None
    - Length between 3 and 30 characters
    - Only alphanumeric characters and underscores allowed (^[a-zA-Z0-9_]{3,30}$)
    """
    if not username or not isinstance(username, str):
        return False, "Username is required."

    cleaned_username = username.strip()

    if len(cleaned_username) < 3 or len(cleaned_username) > 30:
        return False, "Username must be between 3 and 30 characters in length."

    if not USERNAME_REGEX.match(cleaned_username):
        return False, "Username may only contain letters, numbers, and underscores (no spaces or special symbols)."

    return True, None


def validate_password(password: str | None) -> tuple[bool, str | None]:
    r"""
    Enforce defensive password complexity and length requirements.

    Rules:
    - Must not be empty or None
    - Minimum length: 12 characters (defense against dictionary/brute-force attacks)
    - Maximum length: 128 characters (mitigates denial-of-service against hashing algorithm)
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one numeric digit (0-9)
    - At least one special symbol (!@#$%^&*(),.?":{}|<>\-_=+)
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."

    if len(password) < 12:
        return False, "Password must be at least 12 characters in length."

    if len(password) > 128:
        return False, "Password must not exceed 128 characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one numeric digit (0-9)."

    if not SPECIAL_CHARS_REGEX.search(password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>-=_+)."

    return True, None
