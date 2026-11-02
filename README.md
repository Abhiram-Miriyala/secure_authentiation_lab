# 🛡️ Secure Authentication Lab

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1%2B-black.svg)](https://palletsprojects.com/p/flask/)
[![Password Hashing](https://img.shields.io/badge/Argon2id-PHC%20Winner-success.svg)](https://github.com/P-H-C/phc-winner-argon2)
[![Testing](https://img.shields.io/badge/Pytest-15%2F15%20Passing-brightgreen.svg)](https://pytest.org/)
[![Security](https://img.shields.io/badge/Defense-In--Depth-blueviolet.svg)](#security-controls-explanation)

A reference cybersecurity project demonstrating modern defensive authentication controls in Python and Flask. Built to showcase enterprise-grade authentication defenses, including **Argon2id** password hashing, **generic error messages with timing attack mitigation**, **session fixation countermeasures**, **hardened cookie attributes**, **rate limiting**, and **parameterized SQL queries**.

---

## 📋 Table of Contents

- [1. Project Introduction](#1-project-introduction)
- [2. Project Objectives](#2-project-objectives)
- [3. Architecture & Technologies](#3-architecture--technologies)
- [4. Core Defensive Features](#4-core-defensive-features)
- [5. Project Folder Structure](#5-project-folder-structure)
- [6. Installation & Execution Guide](#6-installation--execution-guide)
  - [Linux (Kali / Ubuntu / Debian)](#linux-kali--ubuntu--debian)
  - [Windows (PowerShell)](#windows-powershell)
- [7. Automated Security Testing](#7-automated-security-testing)
- [8. Security Controls Explanation](#8-security-controls-explanation)
- [9. Visual Interface & Walkthrough](#9-visual-interface--walkthrough)
- [10. Production Considerations & Future Improvements](#10-production-considerations--future-improvements)

---

## 1. Project Introduction

Authentication systems are among the most heavily targeted entry points in modern web applications. Attackers routinely deploy automated credential stuffing, brute-forcing, SQL injection, user enumeration via timing discrepancies, and session hijacking against poorly defended login portals.

The **Secure Authentication Lab** is an end-to-end, working defensive implementation designed to prove how secure coding practices and defensive controls completely neutralize these attack vectors.

---

## 2. Project Objectives

1. **Eliminate Password Cracking Feasibility:** Implement **Argon2id** password hashing with 64MB memory hardness and 3 iterations to thwart GPU/ASIC hardware acceleration.
2. **Prevent User Enumeration:** Enforce generic authentication errors and perform constant-time dummy verifications to defeat statistical response-timing attacks.
3. **Neutralize SQL Injection:** Use strictly parameterized queries with bound variables (`?`) for all database operations.
4. **Harden Session Lifecycles:** Mitigate session fixation by completely regenerating the session state upon login, protecting cookies with `HttpOnly`, `SameSite=Lax`, and `Secure` attributes, and enforcing an inactivity timeout.
5. **Thwart Brute-Force & Credential Stuffing:** Restrict login attempts to 5 per minute per IP using `Flask-Limiter`, returning `HTTP 429 Too Many Requests`.
6. **Defend Against CSRF:** Enforce anti-CSRF token verification across all state-changing endpoints.
7. **Verify via Automated Testing:** Validate all 15 defensive specifications with executable Pytest test cases.

---

## 3. Architecture & Technologies

| Layer | Technology | Defensive Role |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.10+ / Flask 3.1+ | Application routing and middleware pipeline |
| **Password Hashing** | `argon2-cffi` (Argon2id) | Memory-hard key derivation resistant to GPUs/ASICs |
| **Database** | SQLite 3 (`sqlite3`) | Parameterized SQL queries preventing injection |
| **Rate Limiting** | `Flask-Limiter` | Fixed-window abuse defense returning HTTP 429 |
| **CSRF Protection** | `Flask-WTF` | Cryptographically signed tokens per session |
| **Session Engine** | Flask Signed Cookies | `HttpOnly`, `SameSite=Lax`, `Secure`, 30-min timeout |
| **Frontend** | HTML5, CSS3, Bootstrap 5, JS | Responsive cybersecurity-themed interface with real-time strength meter |
| **Test Automation** | `pytest`, `pytest-flask` | Automated verification of all 15 security requirements |

---

## 4. Core Defensive Features

### A. Defensive Registration
- Strict server-side username validation (`^[a-zA-Z0-9_]{3,30}$`).
- Multi-factor password complexity enforcement (minimum 12 chars, uppercase, lowercase, digit, special character).
- Algorithmic DoS mitigation (maximum 128 chars limit to prevent CPU/memory exhaustion during hashing).
- Duplicate username detection with secure database constraint handling.
- Passwords hashed immediately using Argon2id with cryptographically secure random salts.

### B. Hardened Authentication & Timing Equalization
- Parameterized lookups prevent SQL injection (`SELECT ... WHERE username = ?`).
- Constant-time response: If a username does not exist, the server executes `dummy_verify()` on a precomputed dummy hash, ensuring response times between existing and non-existing accounts are statistically indistinguishable.
- Identical error message (`"Invalid username or password."`) and status code (`401 Unauthorized`) for all failures.

### C. Session Fixation & Cookie Hardening
- Upon successful login, `session.clear()` wipes any pre-authentication session tokens, issuing a completely fresh session identifier.
- `HttpOnly` flag prevents client-side JavaScript access via `document.cookie` (defense against XSS).
- `SameSite=Lax` ensures cookies are not sent during third-party cross-site requests.
- Server-side inactivity expiration window (default: 30 minutes).

### D. Rate Limiting Protection
- Sensitive authentication routes are capped at **5 requests per minute** per client IP.
- Excess requests immediately yield `HTTP 429 Too Many Requests`.

---

## 5. Project Folder Structure

```
secure-authentication-lab/
│
├── app/
│   ├── __init__.py          # Application Factory, CSRF/Limiter setup, HTTP security headers
│   ├── routes.py            # Public, authenticated, and authentication route controllers
│   ├── auth.py              # @login_required decorator, session fixation & timeout handlers
│   ├── models.py            # Parameterized SQLite queries & database schema management
│   ├── security.py          # Argon2id hashing, dummy verification & server-side validators
│   ├── config.py            # Development, Testing, and Production configuration classes
│   ├── templates/
│   │   ├── base.html        # Master cybersecurity layout with navbar and flash messages
│   │   ├── index.html       # Landing page detailing architecture and controls
│   │   ├── login.html       # Rate-limited authentication form
│   │   ├── register.html    # Registration with real-time password complexity checklist
│   │   ├── dashboard.html   # Authenticated dashboard displaying active session parameters
│   │   ├── security.html    # Comprehensive technical security reference page
│   │   └── 429.html         # Custom error template for rate limits and CSRF issues
│   └── static/
│       ├── css/
│       │   └── style.css    # Dark navy cybersecurity theme with cyan glow accents
│       └── js/
│           └── script.js    # Client-side password strength meter & visibility toggles
│
├── tests/
│   ├── conftest.py          # Pytest fixtures and isolated temporary database
│   ├── test_auth.py         # Registration, login, logout, and generic error tests
│   ├── test_security.py     # Argon2id verification, session expiration, cookies, SQL injection
│   └── test_rate_limit.py   # Rate limiting trigger (HTTP 429) test
│
├── instance/                # Local SQLite database directory (git-ignored)
├── requirements.txt         # Pinned production and testing dependencies
├── pytest.ini               # Pytest configuration
├── .env.example             # Template for environment-specific secrets
├── .gitignore               # Excludes secrets, databases, and temporary files
├── run.py                   # Development server entry point
├── README.md                # Comprehensive project documentation
└── SECURITY.md              # In-depth security analysis and threat modeling
```

---

## 6. Installation & Execution Guide

### Linux (Kali / Ubuntu / Debian)

Open your terminal and execute the following commands step by step:

```bash
# 1. Update system packages and install Python3 development tools
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# 2. Clone or navigate to the project directory
git clone https://github.com/<your-username>/secure-authentication-lab.git
cd secure-authentication-lab

# 3. Create a dedicated Python virtual environment
python3 -m venv venv

# 4. Activate the virtual environment
source venv/bin/activate

# 5. Upgrade pip and install all project dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Set up your local environment file
cp .env.example .env

# Generate a strong 32-byte (64 hex characters) secret key and save it to .env:
python3 -c "import secrets; print(f'SECRET_KEY={secrets.token_hex(32)}')" >> .env

# 7. Initialize the SQLite database schema
flask --app run:app init-db

# 8. Start the local Flask development server
python run.py
```

The application will be live at: **`http://127.0.0.1:5000`**

---

### Windows (PowerShell)

```powershell
# 1. Navigate to the project directory
cd secure-authentication-lab

# 2. Create and activate a Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Create local .env configuration
Copy-Item .env.example .env

# 5. Initialize the SQLite database
flask --app run:app init-db

# 6. Run the server
python run.py
```

---

## 7. Automated Security Testing

All 15 security specifications are backed by automated Pytest unit and integration tests.

### Running the Test Suite

With your virtual environment active, run:

```bash
pytest -v
```

### Verified Test Cases

| # | Test Name | File | Description | Status |
| :---: | :--- | :--- | :--- | :---: |
| 1 | `test_successful_registration` | `test_auth.py` | Valid registration creates user and redirects | **PASSED** |
| 2 | `test_duplicate_username_rejection` | `test_auth.py` | Duplicate username yields HTTP 400 | **PASSED** |
| 3 | `test_password_hashing_verification` | `test_security.py` | Argon2id format `$argon2id$v=19$m=65536...` | **PASSED** |
| 4 | `test_no_plaintext_passwords_stored` | `test_security.py` | Plaintext string does not exist anywhere in DB | **PASSED** |
| 5 | `test_successful_login` | `test_auth.py` | Valid credentials establish session and redirect | **PASSED** |
| 6 | `test_incorrect_password_rejection` | `test_auth.py` | Invalid password returns HTTP 401 | **PASSED** |
| 7 | `test_nonexistent_username_rejection`| `test_auth.py` | Unknown username returns HTTP 401 | **PASSED** |
| 8 | `test_generic_error_message_consistency` | `test_auth.py` | Identical message & 401 code for unknown user vs bad pass | **PASSED** |
| 9 | `test_unauthorized_dashboard_access`| `test_auth.py` | Unauthenticated access redirects to login | **PASSED** |
| 10 | `test_successful_logout` | `test_auth.py` | Session invalidated; dashboard access denied | **PASSED** |
| 11 | `test_session_expiration` | `test_security.py` | Stale session past 30-min window rejected | **PASSED** |
| 12 | `test_secure_cookie_configuration` | `test_security.py` | HttpOnly, SameSite=Lax, and Secure flags verified | **PASSED** |
| 13 | `test_server_side_input_validation` | `test_security.py` | Rejects short/long/malformed users & weak passwords | **PASSED** |
| 14 | `test_login_rate_limiting` | `test_rate_limit.py`| 6th attempt within 1 minute returns HTTP 429 | **PASSED** |
| 15 | `test_sql_injection_resistance` | `test_security.py` | Hostile injection payloads treated as literal text | **PASSED** |

---

## 8. Security Controls Explanation

### 1. Argon2id Password Hashing
Argon2 won the international Password Hashing Competition (PHC). Argon2id is a hybrid mode:
- **Argon2d component:** Resists GPU and ASIC brute-forcing by making memory access data-dependent.
- **Argon2i component:** Resists side-channel cache timing attacks by making memory access data-independent.
- **Parameters:** Configured with `m=65536` (64 MB of RAM per hash), `t=3` (3 iterations), and `p=4` (4 threads).

### 2. Constant-Time Dummy Verification (Timing Attack Defense)
In naive authentication systems:
- Unregistered username $\rightarrow$ Database query returns empty $\rightarrow$ Fast response ($\sim 2\text{ms}$).
- Registered username $\rightarrow$ Database returns user $\rightarrow$ Argon2id hash computed $\rightarrow$ Slower response ($\sim 60\text{ms}$).

Attackers exploit this $\sim 58\text{ms}$ discrepancy to enumerate valid usernames.  
**Our Defense:** If the username lookup yields `None`, the server immediately executes `dummy_verify(password)` against a precomputed dummy hash. Both paths perform identical cryptographic work, defeating timing analysis.

### 3. Session Fixation Mitigation
Session fixation occurs when an attacker forces a victim to use a known session identifier, then hijacks it after the victim logs in.  
**Our Defense:** When a user logs in, `establish_session()` calls `session.clear()`, wiping all existing cookies and session data. A fresh session is generated with a new cryptographic token and a refreshed activity timestamp.

### 4. Parameterized SQL Queries
SQL injection occurs when input strings are concatenated directly into SQL command strings. In this lab, queries strictly use `?` parameter placeholders:
```python
cursor.execute("SELECT id, password_hash FROM users WHERE username = ?;", (username,))
```
The database engine parses and compiles the query structure *first*, treating parameters strictly as data values.

---

## 9. Visual Interface & Walkthrough

The interface is built with a responsive, dark navy cybersecurity theme (`#070d19`) with electric cyan highlights (`#00e5ff`):

1. **Home Page (`/`):** Explains the defensive security architecture and displays an interactive active defense matrix.
2. **Registration Page (`/register`):** Features a real-time password complexity checklist and dynamic strength meter.
3. **Login Page (`/login`):** Warns the user of the active 5-attempts/min rate limit and demonstrates generic error handling.
4. **Dashboard (`/dashboard`):** Only accessible with an active session. Shows account identity, session creation time, active cookie flags (`HttpOnly`, `SameSite`, `Secure`), and a verified defensive controls checklist.
5. **Security Controls Page (`/security`):** A detailed technical reference explaining Argon2id vs legacy algorithms, timing attacks, session hardening, and rate limiting backends.
6. **Error / Rate Limit Page (`/429`):** Displays a cybersecurity alert explaining that rate limits or CSRF checks were triggered.

---

## 10. Production Considerations & Future Improvements

When deploying to a public-facing production environment:

1. **TLS / HTTPS Termination:** Configure an SSL/TLS certificate (e.g. Let's Encrypt) and set `SESSION_COOKIE_SECURE=True` in `.env`.
2. **Distributed Rate Limiting:** Transition `RATELIMIT_STORAGE_URI` from `memory://` to a managed Redis cluster (`redis://:password@redis-server:6379/0`) so limits are synchronized across multi-worker WSGI instances (e.g., Gunicorn or uWSGI).
3. **Multi-Factor Authentication (MFA):** Integrate TOTP (RFC 6238) using libraries like `pyotp` for secondary verification.
4. **Account Lockout Policy:** Add temporary exponential backoff lockouts tied to user accounts after consecutive failed attempts.
5. **Reverse Proxy Trust:** When deploying behind Nginx or Cloudflare, configure `werkzeug.middleware.proxy_fix.ProxyFix` to prevent spoofing of client IP addresses via forged `X-Forwarded-For` headers.

---

## 📄 License & Attribution

Designed and developed as an academic and professional cybersecurity reference implementation for **EdVyro** project review. Free for educational and training purposes.
