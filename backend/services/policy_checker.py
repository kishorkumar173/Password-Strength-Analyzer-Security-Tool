"""
Password Policy Checker Service.
Evaluates passwords against customizable enterprise and standards-based security policies.
Specifically highlights alignment with NIST SP 800-63B (Digital Identity Guidelines).
Separates Policy Compliance (PASS/FAIL) from Password Strength (0-100 Score).
"""

from typing import Dict, Any, List, Optional
from backend.services.common_password_checker import is_common_password
from backend.services.context_checker import check_personal_context


class PasswordPolicyChecker:
    def __init__(
        self,
        min_length: int = 12,
        max_length: int = 128,
        require_lowercase: bool = False,
        require_uppercase: bool = False,
        require_digits: bool = False,
        require_symbols: bool = False,
        reject_common: bool = True,
        allow_spaces: bool = True,
        reject_personal_context: bool = True
    ):
        self.min_length = min_length
        self.max_length = max_length
        self.require_lowercase = require_lowercase
        self.require_uppercase = require_uppercase
        self.require_digits = require_digits
        self.require_symbols = require_symbols
        self.reject_common = reject_common
        self.allow_spaces = allow_spaces
        self.reject_personal_context = reject_personal_context

    def evaluate(
        self,
        password: str,
        first_name: Optional[str] = None,
        birth_year: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Evaluates the password against the active policy configuration.

        Distinction:
          - Strength Score measures mathematical and pattern resistance to guessing.
          - Policy Compliance measures binary conformance to organizational rules.
          A password can be strong yet fail a legacy policy, or satisfy a policy yet be weak.

        Returns:
          Dict with status (PASS/FAIL), rules_evaluated, failed_rules, and NIST guidance.
        """
        rules_evaluated: List[Dict[str, Any]] = []
        failed_rules: List[str] = []

        length = len(password) if password else 0

        # Rule 1: Minimum Length
        passed_min = length >= self.min_length
        rules_evaluated.append({
            "rule": "Minimum Length Requirement",
            "threshold": f">= {self.min_length} characters",
            "status": "PASS" if passed_min else "FAIL",
            "detail": f"Actual length: {length}"
        })
        if not passed_min:
            failed_rules.append(f"Must be at least {self.min_length} characters (current: {length})")

        # Rule 2: Maximum Length
        passed_max = length <= self.max_length
        rules_evaluated.append({
            "rule": "Maximum Length Limit",
            "threshold": f"<= {self.max_length} characters",
            "status": "PASS" if passed_max else "FAIL",
            "detail": f"Actual length: {length}"
        })
        if not passed_max:
            failed_rules.append(f"Exceeds maximum limit of {self.max_length} characters")

        # Rule 3: Reject Known Common Passwords (NIST Recommendation)
        if self.reject_common:
            common_check = is_common_password(password)
            passed_common = not common_check.get("is_common", False)
            rules_evaluated.append({
                "rule": "Dictionary & Common Password Blacklist",
                "threshold": "Must not exist in known common password lists",
                "status": "PASS" if passed_common else "FAIL",
                "detail": common_check.get("message", "Passed common blacklist check")
            })
            if not passed_common:
                failed_rules.append("Matches a known common password or predictable dictionary mutation")

        # Rule 4: Reject Personal Information Context
        if self.reject_personal_context and (first_name or birth_year or organization):
            context_check = check_personal_context(password, first_name, birth_year, organization)
            passed_context = not context_check.get("has_context_overlap", False)
            rules_evaluated.append({
                "rule": "Personal Context Blacklist",
                "threshold": "Must not contain user's name, birth year, or organization",
                "status": "PASS" if passed_context else "FAIL",
                "detail": context_check.get("message")
            })
            if not passed_context:
                failed_rules.append(f"Contains personal context: {', '.join(context_check.get('matched_items', []))}")

        # Rule 5: Spaces Allowed (NIST Recommendation)
        if " " in password:
            rules_evaluated.append({
                "rule": "Space Character Support",
                "threshold": "Spaces are valid passphrase separators",
                "status": "PASS" if self.allow_spaces else "FAIL",
                "detail": "Password contains whitespace characters"
            })
            if not self.allow_spaces:
                failed_rules.append("Spaces are prohibited by this specific policy")

        # Legacy Composition Rules (Optional)
        if self.require_lowercase:
            has_lower = any(c.islower() for c in password)
            rules_evaluated.append({
                "rule": "Lowercase Character Required",
                "threshold": ">= 1 lowercase letter",
                "status": "PASS" if has_lower else "FAIL",
                "detail": "Present" if has_lower else "Missing"
            })
            if not has_lower:
                failed_rules.append("Must include at least one lowercase letter")

        if self.require_uppercase:
            has_upper = any(c.isupper() for c in password)
            rules_evaluated.append({
                "rule": "Uppercase Character Required",
                "threshold": ">= 1 uppercase letter",
                "status": "PASS" if has_upper else "FAIL",
                "detail": "Present" if has_upper else "Missing"
            })
            if not has_upper:
                failed_rules.append("Must include at least one uppercase letter")

        if self.require_digits:
            has_digit = any(c.isdigit() for c in password)
            rules_evaluated.append({
                "rule": "Digit Character Required",
                "threshold": ">= 1 numeric digit",
                "status": "PASS" if has_digit else "FAIL",
                "detail": "Present" if has_digit else "Missing"
            })
            if not has_digit:
                failed_rules.append("Must include at least one numeric digit")

        if self.require_symbols:
            import string
            has_sym = any(c in string.punctuation for c in password)
            rules_evaluated.append({
                "rule": "Special Symbol Required",
                "threshold": ">= 1 punctuation / symbol",
                "status": "PASS" if has_sym else "FAIL",
                "detail": "Present" if has_sym else "Missing"
            })
            if not has_sym:
                failed_rules.append("Must include at least one special character")

        overall_status = "PASS" if len(failed_rules) == 0 else "FAIL"

        nist_alignment = {
            "sp800_63b_compliant": (
                self.min_length >= 8 and
                self.max_length >= 64 and
                self.reject_common and
                self.allow_spaces and
                not (self.require_uppercase or self.require_digits or self.require_symbols)
            ),
            "commentary": (
                "NIST SP 800-63B emphasizes length (>= 8, ideally 12+), blacklist screening against "
                "compromised credentials, and supporting spaces. NIST explicitly advises against "
                "forcing composition complexity rules (such as requiring mixed characters) because "
                "they lead humans to adopt predictable substitutions (e.g. 'Password123!')."
            )
        }

        return {
            "status": overall_status,
            "passed": overall_status == "PASS",
            "total_rules": len(rules_evaluated),
            "failed_count": len(failed_rules),
            "failed_rules": failed_rules,
            "rules": rules_evaluated,
            "nist_guidance": nist_alignment
        }
