"""
Character Diversity Analysis Service.
Detects presence of character types, unique character ratios, and pool size.
Educates why composition rules alone are insufficient for real security.
"""

import string
from typing import Dict, Any


def analyze_characters(password: str) -> Dict[str, Any]:
    """
    Analyzes character set distribution, uniqueness, and diversity.

    Evaluates:
      - Lowercase letters (a-z)
      - Uppercase letters (A-Z)
      - Digits (0-9)
      - Symbols / Punctuation (!@#$%^&*...)
      - Whitespace
      - Unique character count and ratio
      - Estimated character pool size (N)

    Returns:
      Structured character metric dictionary.
    """
    if not password:
        return {
            "has_lowercase": False,
            "has_uppercase": False,
            "has_digits": False,
            "has_symbols": False,
            "has_spaces": False,
            "lowercase_count": 0,
            "uppercase_count": 0,
            "digit_count": 0,
            "symbol_count": 0,
            "space_count": 0,
            "unique_character_count": 0,
            "character_type_count": 0,
            "unique_character_ratio": 0.0,
            "estimated_pool_size": 0,
            "score_contribution": 0,
            "educational_note": "No characters detected."
        }

    symbols_set = set(string.punctuation)
    length = len(password)

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_spaces = any(c.isspace() for c in password)
    has_symbols = any(c in symbols_set for c in password)

    lower_count = sum(1 for c in password if c.islower())
    upper_count = sum(1 for c in password if c.isupper())
    digit_count = sum(1 for c in password if c.isdigit())
    space_count = sum(1 for c in password if c.isspace())
    symbol_count = sum(1 for c in password if c in symbols_set)

    unique_chars = len(set(password))
    unique_ratio = round(unique_chars / length, 3) if length > 0 else 0.0

    # Count character types present (excluding whitespace as a standard type, but noted)
    type_count = sum([has_lower, has_upper, has_digits, has_symbols])

    # Estimated character pool size (N) for theoretical entropy calculations
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33
    if has_spaces:
        pool_size += 1

    # Score contribution (up to 15 for variety + up to 10 for uniqueness ratio)
    variety_score = 0
    if type_count == 4:
        variety_score = 15
    elif type_count == 3:
        variety_score = 10
    elif type_count == 2:
        variety_score = 6
    elif type_count == 1:
        variety_score = 2

    # Uniqueness bonus: penalize heavily repeated characters
    uniqueness_score = 0
    if unique_ratio >= 0.8:
        uniqueness_score = 10
    elif unique_ratio >= 0.6:
        uniqueness_score = 7
    elif unique_ratio >= 0.4:
        uniqueness_score = 4
    else:
        uniqueness_score = 1

    total_char_score = variety_score + uniqueness_score

    educational_note = (
        f"Detected {type_count} of 4 standard character classes with a unique character ratio of "
        f"{unique_ratio:.0%}. Note: A password like 'Password123!' uses all 4 classes but remains "
        f"predictable due to human habit and structural pattern conventions."
    )

    return {
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "has_spaces": has_spaces,
        "lowercase_count": lower_count,
        "uppercase_count": upper_count,
        "digit_count": digit_count,
        "symbol_count": symbol_count,
        "space_count": space_count,
        "unique_character_count": unique_chars,
        "character_type_count": type_count,
        "unique_character_ratio": unique_ratio,
        "estimated_pool_size": pool_size,
        "variety_score": variety_score,
        "uniqueness_score": uniqueness_score,
        "score_contribution": total_char_score,
        "educational_note": educational_note
    }
