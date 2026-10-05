"""
Length Analysis Service for Password Strength Analyzer.
Evaluates password length and provides defensive educational feedback.
Emphasizes that length is a fundamental pillar of strength, but length
alone does not guarantee security if predictability is high.
"""

from typing import Dict, Any


def analyze_length(password: str) -> Dict[str, Any]:
    """
    Analyzes password length and categorizes it into educational bands.

    Educational Bands:
      - Less than 8: Very short (Critically vulnerable to brute-force)
      - 8 to 11:     Short (Legacy minimum, inadequate for modern threats)
      - 12 to 15:    Better length (Modern standard minimum for user accounts)
      - 16+:         Strong length contribution (Dramatically increases theoretical search space)

    Returns:
      Dict with length, band, description, score_contribution, and educational_note.
    """
    length = len(password) if password else 0

    if length == 0:
        return {
            "length": 0,
            "band": "Empty",
            "description": "No password entered.",
            "score_contribution": 0,
            "status": "danger",
            "educational_note": "A password cannot be evaluated without characters."
        }

    if length < 8:
        return {
            "length": length,
            "band": "Very Short",
            "description": f"Length is {length} characters. Below minimum safety baseline of 8 characters.",
            "score_contribution": 5,
            "status": "danger",
            "educational_note": (
                "Passphrases or passwords under 8 characters can be searched exhaustively "
                "in a very short time on modern computing hardware."
            )
        }
    elif 8 <= length <= 11:
        return {
            "length": length,
            "band": "Short",
            "description": f"Length is {length} characters. Meets legacy threshold but vulnerable to modern cracking.",
            "score_contribution": 15,
            "status": "warning",
            "educational_note": (
                "While 8-11 characters was historically common, modern standards (e.g., NIST SP 800-63B) "
                "recommend at least 12-16 characters for resilient human accounts."
            )
        }
    elif 12 <= length <= 15:
        return {
            "length": length,
            "band": "Better Length",
            "description": f"Length is {length} characters. Strong base length for general consumer accounts.",
            "score_contribution": 25,
            "status": "info",
            "educational_note": (
                "12 to 15 characters significantly expands the combinatorial search space, "
                "provided it is not composed of simple predictable words."
            )
        }
    else:  # 16+
        return {
            "length": length,
            "band": "Strong Length Contribution",
            "description": f"Length is {length} characters. Excellent length defense against offline attacks.",
            "score_contribution": 35,
            "status": "success",
            "educational_note": (
                "Lengths of 16+ characters offer exponential resistance against brute-force attacks. "
                "Note: Length must still be paired with pattern unpredictability."
            )
        }
