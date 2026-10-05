"""
Educational Password Hashing API Routes.
Exposes endpoints demonstrating salt, key stretching, work factor, and constant-time verification.
"""

from flask import Blueprint, request, jsonify
from backend.services.hashing_demo import demonstrate_hashing, verify_demo_password

hashing_bp = Blueprint("hashing_bp", __name__)


@hashing_bp.route("/demo-hash", methods=["POST"])
def demo_hash_endpoint():
    """
    POST /api/demo-hash
    Payload:
      {
        "password": "SyntheticDemoPassword42!",
        "iterations": 100000
      }
    """
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "SyntheticDemoPassword42!")
        iterations = min(600000, max(10000, int(data.get("iterations", 100000))))

        result = demonstrate_hashing(password, iterations=iterations)
        return jsonify({
            "status": "success",
            "data": result
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Hashing demonstration error: {str(e)}"
        }), 500


@hashing_bp.route("/demo-verify", methods=["POST"])
def demo_verify_endpoint():
    """
    POST /api/demo-verify
    Payload:
      {
        "password": "...",
        "storage_string": "..."
      }
    """
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")
        storage_string = data.get("storage_string", "")

        result = verify_demo_password(password, storage_string)
        return jsonify({
            "status": "success",
            "data": result
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Verification error: {str(e)}"
        }), 500
