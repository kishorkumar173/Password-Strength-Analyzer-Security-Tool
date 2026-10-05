"""
Analytics & Dashboard API Routes.
Provides aggregate anonymous telemetry for SOC / IAM dashboards.
Guaranteed to never contain plaintext credentials or hashes.
"""

from flask import Blueprint, jsonify
from backend.database import get_dashboard_statistics, reset_analytics_data, seed_demo_telemetry_if_empty

analytics_bp = Blueprint("analytics_bp", __name__)


@analytics_bp.route("/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    """
    GET /api/dashboard/stats
    Returns aggregated metrics:
      - Total analyses
      - Average score & length
      - Strength classification counts
      - Common weakness frequencies
      - Score distribution histogram
    """
    try:
        stats = get_dashboard_statistics()
        return jsonify({
            "status": "success",
            "data": stats
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve dashboard statistics: {str(e)}"
        }), 500


@analytics_bp.route("/dashboard/reset", methods=["POST"])
def reset_dashboard():
    """
    POST /api/dashboard/reset
    Clears test telemetry for a fresh test run.
    """
    try:
        reset_analytics_data()
        return jsonify({
            "status": "success",
            "message": "Analytics database successfully reset."
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to reset database: {str(e)}"
        }), 500


@analytics_bp.route("/dashboard/seed-demo", methods=["POST"])
def seed_demo_data():
    """
    POST /api/dashboard/seed-demo
    Populates synthetic demonstration data so charts render beautifully.
    """
    try:
        seed_demo_telemetry_if_empty()
        return jsonify({
            "status": "success",
            "message": "Sample telemetry seeded successfully."
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to seed demo data: {str(e)}"
        }), 500
