# 🔒 Security Policy & Architectural Threat Model

This document outlines the security specifications, threat mitigations, cryptographic foundations, and production deployment considerations for the **Secure Authentication Lab**.

---

## 1. Password Storage & Hashing: Why Argon2id?

### The Problem with Legacy Algorithms
- **MD5 & SHA-1 / SHA-256:** Cryptographic hash functions designed for speed and data integrity, not password storage. Modern consumer GPUs (e.g., NVIDIA RTX 4090) can compute billions of SHA-256 hashes per second, making offline dictionary attacks instantaneous.
- **Bcrypt:** While historically robust, Bcrypt requires very little memory ($\approx 4\text{ KB}$). Specialized ASICs (Application-Specific Integrated Circuits) and FPGAs can crack Bcrypt at low cost because they can pack thousands of parallel cracking cores into a single chip without requiring substantial RAM.
- **PBKDF2:** Heavily susceptible to GPU/ASIC acceleration because it uses repetitive SHA-1/SHA-256 operations with zero memory hardness.

### The Solution: Argon2id (PHC Winner)
Argon2 was selected as the winner of the international **Password Hashing Competition (PHC)** in July 2015. It exists in three variants:
1. **Argon2d:** Data-dependent memory access. Extremely resistant to GPU cracking, but vulnerable to side-channel cache timing attacks.
2. **Argon2i:** Data-independent memory access. Immune to side-channel cache timing attacks, but slightly less resistant to GPU memory-tradeoff attacks.
3. **Argon2id (Used in this Lab):** A hybrid of Argon2i and Argon2d. It begins in Argon2i mode to neutralize side-channel cache attacks during the initial memory passes, and transitions to Argon2d mode to maximize ASIC/GPU brute-force defense.

### Cryptographic Configuration in this Lab
Configured via `argon2-cffi`:
```python
PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MiB RAM per calculation
    parallelism=4,      # 4 execution threads
    hash_len=32,        # 256-bit output digest
    type=argon2.Type.ID # Argon2id hybrid mode
)
```

**Defensive Impact:** An attacker attempting to crack an Argon2id database offline requires 64 MB of dedicated RAM per single guess. An attacker attempting 1,000,000 parallel guesses would require **64 Terabytes of ultra-fast memory**, rendering hardware-accelerated dictionary attacks economically infeasible.

---

## 2. Session Security Architecture

HTTP is a stateless protocol. Session cookies represent the authenticated identity of the user. If an attacker captures or manipulates this cookie, they obtain full unauthorized access to the victim's account without knowing their password.

### Countermeasures Implemented:

| Control | Implementation | Threat Mitigated |
| :--- | :--- | :--- |
| **HttpOnly Flag** | `SESSION_COOKIE_HTTPONLY = True` | **Cross-Site Scripting (XSS):** Prevents malicious scripts from reading `document.cookie`. |
| **SameSite Flag** | `SESSION_COOKIE_SAMESITE = 'Lax'` | **Cross-Site Request Forgery (CSRF):** Withholds cookie during cross-origin requests. |
| **Secure Flag** | `SESSION_COOKIE_SECURE = True` (in prod) | **Man-in-the-Middle (MitM):** Forbids transmission over plaintext HTTP. |
| **Session Fixation Defense**| `session.clear()` on login | **Session Fixation:** Destroys pre-auth session IDs; issues fresh signed token. |
| **Inactivity Expiration** | `PERMANENT_SESSION_LIFETIME = 30m` | **Stale Session Abuse:** Automatically invalidates idle browser sessions. |

### Session Fixation Deep Dive
In a session fixation attack, an adversary tricks a user into authenticating using a known session ID (e.g., via query string or pre-planted cookie). If the server preserves the session identifier across the privilege boundary, the adversary gains authenticated access.

**Our Mitigation:**
In `app/auth.py`, when a user successfully enters their credentials:
```python
def establish_session(user):
    # 1. Clear any pre-existing session state completely
    session.clear()
    
    # 2. Issue fresh anti-fixation token and session attributes
    session.permanent = True
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['session_token'] = secrets.token_hex(32)
    session['last_active'] = datetime.now(timezone.utc).timestamp()
```

---

## 3. Rate Limiting Architecture

Automated bots conduct **credential stuffing** (testing lists of leaked credentials) and **password spraying** (testing common passwords against multiple usernames).

### Flask-Limiter Implementation
The `/login` endpoint is bound by `@limiter.limit("5 per minute", methods=["POST"])`.
- Tracks incoming client IP addresses using `get_remote_address`.
- Automatically responds with `HTTP 429 Too Many Requests` once a client exceeds 5 failed attempts in a 60-second window.

### Storage Backends: Development vs. Production

```
+--------------------------------------------------------------------------+
|                      RATE LIMIT STORAGE COMPARISON                       |
+-----------------------------------+--------------------------------------+
| Development: memory://            | Production: redis://                 |
+-----------------------------------+--------------------------------------+
| - Stored in Python process RAM.   | - Stored in a high-speed key-value   |
| - Zero configuration required.    |   Redis cluster.                     |
| - Resets when process restarts.   | - Shared across multiple load-       |
| - Does NOT sync across multiple   |   balanced Gunicorn / uWSGI workers. |
|   WSGI worker processes.          | - Persists across worker restarts.   |
+-----------------------------------+--------------------------------------+
```

---

## 4. Server-Side Input Validation

Client-side JavaScript validation provides immediate visual feedback to legitimate users, but provides **zero defensive security**. Attackers bypass client-side validation effortlessly using `curl`, Burp Suite, or Python scripts.

### Server-Side Validation Rules (`app/security.py`)
1. **Username Whitelist:**
   - Enforces regex: `^[a-zA-Z0-9_]{3,30}$`
   - Rejects special punctuation, HTML entities, whitespace, and path traversal tokens.
2. **Password Length & Complexity Bounds:**
   - Minimum: 12 characters.
   - Maximum: 128 characters.
   - Must contain: $\ge 1$ uppercase, $\ge 1$ lowercase, $\ge 1$ digit, and $\ge 1$ special character (`[!@#$%^&*(),.?":{}|<>\-_=+]`).
3. **Algorithmic Denial of Service (DoS) Prevention:**
   Because Argon2id is intentionally computationally heavy (consuming 64MB RAM and 3 iterations), submitting a 10MB string as a password would exhaust server RAM and freeze the CPU thread. The server enforces a strict upper limit of 128 characters on passwords to prevent hashing DoS.

---

## 5. Generic Authentication Errors & Timing Attack Mitigation

### Account Enumeration Vulnerability
Traditional authentication endpoints leak information through disparate error messages:
- `"User does not exist"` $\rightarrow$ Tells the attacker the username is invalid.
- `"Incorrect password"` $\rightarrow$ Tells the attacker the username is **valid**, allowing them to focus brute-force resources on that specific account.

### Generic Error Defense
This lab standardizes all login failure responses:
```python
GENERIC_LOGIN_ERROR = "Invalid username or password."
```
Whether the username is non-existent, the password is wrong, or the input is malformed, the application returns the exact same string and `HTTP 401 Unauthorized` status code.

### Side-Channel Timing Attack Neutralization
Even with identical text messages, attackers can measure the server's response latency down to milliseconds.
- If a user does not exist, the database lookup returns immediately ($\approx 2\text{ms}$).
- If a user exists, the server executes Argon2id verification ($\approx 60\text{ms}$).
- The attacker simply checks if the response took $\sim 60\text{ms}$ to confirm the user exists.

**Our Neutralization (`app/security.py`):**
When `user is None`, the server calls:
```python
dummy_verify(password)
```
This executes `hasher.verify(DUMMY_HASH, password)` against a precomputed dummy hash, ensuring that the computational time consumed is identical regardless of whether the user exists in the database.

---

## 6. CSRF (Cross-Site Request Forgery) Protection

Cross-Site Request Forgery forces an authenticated victim's browser to execute unauthorized state-changing actions (e.g., submitting a POST request to update settings or logout).

### Defenses Implemented:
1. **Cryptographic Tokens (`Flask-WTF`):** Every state-changing form includes a hidden `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`. Tokens are unique per session and verified on the server before request processing.
2. **SameSite Cookie Attribute (`Lax`):** Modern browsers withhold the session cookie during cross-origin form submissions, providing defense-in-depth even if a CSRF token check is misconfigured.

---

## 7. Security Limitations & Production Hardening

While this application implements enterprise-level controls for local execution, moving to public production requires the following architectural components:

1. **Reverse Proxy (Nginx) & TLS Termination:**
   - Never expose Flask's built-in development server directly to the internet.
   - Deploy behind Nginx or Cloudflare with strict TLS 1.3 encryption.
   - Configure `ProxyFix` middleware from `werkzeug.middleware.proxy_fix` to sanitize client IP headers (`X-Forwarded-For`).
2. **Secret Key Management:**
   - Store `SECRET_KEY` in a dedicated vault (e.g., HashiCorp Vault, AWS Secrets Manager, or Google Cloud Secret Manager).
3. **Database Migration to Client-Server RDBMS:**
   - For high-concurrency production deployments, migrate from SQLite to PostgreSQL or MySQL with connection pooling.
4. **Multi-Factor Authentication (MFA):**
   - Implement Time-based One-Time Passwords (TOTP, RFC 6238) as a second authentication factor.
5. **Centralized SIEM & Audit Monitoring:**
   - Stream the `login_audit` table logs to a Security Information and Event Management (SIEM) platform (e.g., Splunk, Wazuh, or Elastic Security) for automated intrusion detection and anomaly alerts.
