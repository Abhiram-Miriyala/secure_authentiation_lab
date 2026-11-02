"""
Application Entrypoint for Secure Authentication Lab.

Usage:
    python run.py
"""

import os
from app import create_app
from app.config import Config

app = create_app(Config)

if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

    print("=" * 70)
    print("  [+] Starting Secure Authentication Lab Server")
    print(f"  [+] Host: http://{host}:{port}")
    print(f"  [+] Debug Mode: {debug}")
    print("  [+] Defensive Controls Active: Argon2id, Rate Limiter, CSRF, Secure Sessions")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)
