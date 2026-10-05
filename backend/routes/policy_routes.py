"""
Password Policy Checker API Routes.
Evaluates compliance against enterprise and NIST SP 800-63B standards.
"""

from flask import Blueprint, request, jsonify
from backend.services.policy_checker import PasswordPolicyChecker

policy_bp = Blueprint("policy_bp", __name__)


@policy_bp.route("/check-policy", methods=["POST"])
def check_policy_endpoint():
    """
    POST /api/check-policy
    Payload:
      {
        "password": "...",
        "policy": {
          "min_length": 12,
          "max_length": 128,
          "require_lowercase": false,
          "require_uppercase": false,
          "require_digits": false,
          "require_symbols": false,
          "reject_common": true,
          "allow_spaces": true,
          "reject_personal_context": true
        },
        "first_name": "...",
        "birth_year": "...",
        "organization": "..."
      }
    """
    try:
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")
        policy_cfg = data.get("policy", {})

        first_name = data.get("first_name")
        birth_year = data.get("birth_year")
        organization = data.get("organization")

        checker = PasswordPolicyChecker(
            min_length=int(policy_cfg.get("min_length", 12)),
            max_length=int(policy_cfg.get("max_length", 128)),
            require_lowercase=bool(policy_cfg.get("require_lowercase", False)),
            require_uppercase=bool(policy_cfg.get("require_uppercase", False)),
            require_digits=bool(policy_cfg.get("require_digits", False)),
            require_symbols=bool(policy_cfg.get("require_symbols", False)),
            reject_common=bool(policy_cfg.get("reject_common", True)),
            allow_spaces=bool(policy_cfg.get("allow_spaces", True)),
            reject_personal_context=bool(policy_cfg.get("reject_personal_context", True))
        )

        evaluation = checker.evaluate(
            password=password,
            first_name=first_name,
            birth_year=birth_year,
            organization=organization
        )

        return jsonify({
            "status": "success",
            "data": evaluation
        }), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Policy evaluation error: {str(e)}"
        }), 500
