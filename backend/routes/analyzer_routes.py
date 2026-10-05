"""
Analyzer API Routes.
Exposes POST /api/analyze endpoint for ephemeral password strength evaluation.
Enforces zero logging and transient in-memory processing.
"""

from flask import Blueprint, request, jsonify
from backend.services.password_analyzer import analyze_password
from backend.database import record_analysis_metadata
from backend.config import ENABLE_ANALYTICS

analyzer_bp = Blueprint("analyzer_bp", __name__)


@analyzer_bp.route("/analyze", methods=["POST"])
def analyze_endpoint():
    """
    POST /api/analyze
    Payload:
      {
        "password": "<in-memory string>",
        "first_name": "<optional context>",
        "birth_year": "<optional context>",
        "organization": "<optional context>"
      }

    Security Constraints:
      - Raw password is processed in memory and discarded.
      - Never logged to console, disk, or access logs.
      - Never persisted in any database.
    """
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")
        first_name = data.get("first_name")
        birth_year = data.get("birth_year")
        organization = data.get("organization")

        # Execute analysis
        analysis_result = analyze_password(
            password=password,
            first_name=first_name,
            birth_year=birth_year,
            organization=organization
        )

        # Record anonymous metadata (score, classification, pattern flags) if enabled
        # Password itself is NOT passed to the recording function
        if ENABLE_ANALYTICS and password.strip():
            record_analysis_metadata(analysis_result)

        return jsonify({
            "status": "success",
            "data": analysis_result
        }), 200

    except Exception as e:
        # Crucial: Never include raw input in error responses
        return jsonify({
            "status": "error",
            "message": "Internal error occurred during password evaluation. Input was safely discarded."
        }), 500
