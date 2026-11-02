"""
Application Factory for Secure Authentication Lab.

Initializes Flask extensions (CSRFProtect, Limiter), registers blueprints,
configures defensive HTTP security headers, and handles custom security errors.
"""

import os
from flask import Flask, render_template, request, jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import Config
from app.models import close_db, init_db

# Extension singletons
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def create_app(config_class=Config):
    """
    Construct and configure the Flask application instance.
    """
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)

    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # Initialize Extensions
    csrf.init_app(app)
    limiter.init_app(app)

    # Database Context Teardown and CLI command
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        """CLI command to initialize database schema."""
        init_db(app)
        print("[+] Secure database initialized successfully.")

    # Auto-initialize database on application startup if not present
    with app.app_context():
        init_db(app)

    # Register Blueprints
    from app.routes import main_bp, auth_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)

    # ==========================================================================
    # DEFENSIVE HTTP RESPONSE HEADERS (OWASP Recommended)
    # ==========================================================================
    @app.after_request
    def set_defensive_headers(response):
        # Prevent browsers from MIME-sniffing the response away from declared content-type
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent Clickjacking by disabling rendering inside <iframe> or <frame>
        response.headers["X-Frame-Options"] = "DENY"
        
        # Cross-Site Scripting (XSS) Auditor Protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Restrict referrer leakage to third parties
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Restrict dangerous browser features (sensors, camera, microphone)
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # Content Security Policy (CSP)
        # Allows self-hosted assets and verified CDNs for Bootstrap
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:;"
        )
        return response

    # ==========================================================================
    # SECURITY ERROR HANDLERS
    # ==========================================================================
    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Custom handler for Rate Limit Exceeded (HTTP 429)."""
        if request.is_json:
            return jsonify({
                "error": "Too Many Requests",
                "message": "Rate limit exceeded. Please wait before making further attempts."
            }), 429
        return render_template("429.html", error=e.description), 429

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Custom handler for Cross-Site Request Forgery (CSRF) token validation failures."""
        return render_template(
            "429.html",
            custom_title="CSRF Token Validation Failed",
            custom_message="Your security token has expired or is invalid. Please refresh the page and resubmit."
        ), 400

    @app.errorhandler(404)
    def not_found_error(e):
        """Generic 404 handler without leaking file system structure."""
        return render_template(
            "429.html",
            custom_title="404 - Resource Not Found",
            custom_message="The requested endpoint does not exist on this server."
        ), 404

    @app.errorhandler(500)
    def internal_error(e):
        """Generic 500 handler preventing sensitive server stack traces from being exposed."""
        return render_template(
            "429.html",
            custom_title="500 - Internal Security Error",
            custom_message="An internal error occurred. Detailed error details have been logged securely."
        ), 500

    return app
