"""
Password & Passphrase Generator API Routes.
Exposes cryptographically secure generation endpoints.
"""

from flask import Blueprint, request, jsonify
from backend.services.password_generator import (
    generate_secure_password,
    generate_secure_passphrase
)

generator_bp = Blueprint("generator_bp", __name__)


@generator_bp.route("/generate-password", methods=["POST"])
def generate_password_endpoint():
    """
    POST /api/generate-password
    Generates a cryptographically strong random password using CSPRNG secrets.
    """
    try:
        data = request.get_json(silent=True) or {}
        length = int(data.get("length", 16))
        use_upper = bool(data.get("uppercase", True))
        use_lower = bool(data.get("lowercase", True))
        use_digits = bool(data.get("digits", True))
        use_symbols = bool(data.get("symbols", True))

        result = generate_secure_password(
            length=length,
            use_upper=use_upper,
            use_lower=use_lower,
            use_digits=use_digits,
            use_symbols=use_symbols
        )

        return jsonify({
            "status": "success",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to generate secure password: {str(e)}"
        }), 500


@generator_bp.route("/generate-passphrase", methods=["POST"])
def generate_passphrase_endpoint():
    """
    POST /api/generate-passphrase
    Generates a memorable, high-entropy Diceware-style multi-word passphrase.
    """
    try:
        data = request.get_json(silent=True) or {}
        word_count = int(data.get("word_count", 4))
        separator = str(data.get("separator", "-"))

        result = generate_secure_passphrase(
            word_count=word_count,
            separator=separator
        )

        return jsonify({
            "status": "success",
            "data": result
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to generate passphrase: {str(e)}"
        }), 500
