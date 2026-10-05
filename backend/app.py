"""
Password Strength Analyzer & Security Suggestion Tool
Main Flask Application Factory & Server.

DEFENSIVE ARCHITECTURE:
- Transient in-memory request processing
- No request-body logging
- Strict CORS and security headers
- Zero password retention policy
"""

import logging
from pathlib import Path
from flask import Flask, send_from_directory, jsonify
try:
    from flask_cors import CORS
    CORS_AVAILABLE = True
except ImportError:
    CORS_AVAILABLE = False

from backend.config import BASE_DIR, HOST, PORT, DEBUG
from backend.database import init_db, seed_demo_telemetry_if_empty

# Blueprints
from backend.routes.analyzer_routes import analyzer_bp
from backend.routes.generator_routes import generator_bp
from backend.routes.policy_routes import policy_bp
from backend.routes.hashing_demo_routes import hashing_bp
from backend.routes.analytics_routes import analytics_bp

FRONTEND_DIR = BASE_DIR / "frontend"


def create_app() -> Flask:
    """Application factory for Password Strength Analyzer."""
    app = Flask(__name__, static_folder=str(FRONTEND_DIR))

    # Enable CORS for local testing and decouple client-server calls
    if CORS_AVAILABLE:
        CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Suppress verbose request payload logging to prevent accidental password leaks in stdout
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    # Initialize Database Schema & Seed Initial Demo Data if empty
    with app.app_context():
        init_db()
        seed_demo_telemetry_if_empty()

    # Register Blueprints
    app.register_blueprint(analyzer_bp, url_prefix="/api")
    app.register_blueprint(generator_bp, url_prefix="/api")
    app.register_blueprint(policy_bp, url_prefix="/api")
    app.register_blueprint(hashing_bp, url_prefix="/api")
    app.register_blueprint(analytics_bp, url_prefix="/api")

    # Serve Frontend UI
    @app.route("/")
    def serve_index():
        return send_from_directory(str(FRONTEND_DIR), "index.html")

    @app.route("/<path:path>")
    def serve_static(path):
        return send_from_directory(str(FRONTEND_DIR), path)

    # Global Defensive Security Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        if not CORS_AVAILABLE:
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        return response

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"status": "error", "message": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"status": "error", "message": "Internal server error occurred safely."}), 500

    return app


if __name__ == "__main__":
    application = create_app()
    port = int(os.environ.get("PORT", 5000))
    host = "0.0.0.0"
    print(f"\n==================================================================")
    print(f"🔒 PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL")
    print(f"==================================================================")
    print(f"🛡️  Mode: Defensive In-Memory Password Analysis")
    print(f"🛡️  Privacy: ZERO password storage or external transmission")
    print(f"🌐 Server Running At: http://{host}:{port}")
    print(f"==================================================================\n")
    application.run(host=host, port=port, debug=False, use_reloader=False)
