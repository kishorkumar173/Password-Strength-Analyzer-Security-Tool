"""
Repetition Detection Service.
Detects repeated characters (e.g., 'aaaa', '1111') and repeated substrings/cycles
(e.g., 'ababab', 'abcabcabc', 'passpass').
Heavily penalizes repetitive inputs that superficially inflate password length.
"""

import re
from typing import Dict, Any, List


def detect_repetition(password: str) -> Dict[str, Any]:
    """
    Analyzes password for character and substring repetitions.

    Examples:
      - 'aaaaaa' -> 6 identical consecutive characters
      - 'abababab' -> repeated 2-character unit ('ab')
      - 'abcabcabc' -> repeated 3-character unit ('abc')

    Returns:
      Dict with has_repetition, repeated_chars, repeated_substrings, penalty, and details.
    """
    if not password:
        return {
            "has_repetition": False,
            "repeated_chars": [],
            "repeated_substrings": [],
            "max_consecutive_count": 0,
            "penalty": 0,
            "details": []
        }

    repeated_chars: List[Dict[str, Any]] = []
    repeated_substrings: List[Dict[str, Any]] = []
    details: List[str] = []
    penalty = 0

    # 1. Consecutive identical character runs (>= 3 chars, e.g. 'aaa', '111')
    consecutive_matches = re.finditer(r'(.)\1{2,}', password, re.IGNORECASE)
    max_consecutive = 0
    for match in consecutive_matches:
        matched_str = match.group(0)
        char = match.group(1)
        count = len(matched_str)
        if count > max_consecutive:
            max_consecutive = count
        repeated_chars.append({
            "character": char,
            "count": count,
            "sequence": matched_str,
            "start": match.start()
        })
        run_penalty = min(20, count * 3)
        penalty += run_penalty
        details.append(f"Repeated character '{char}' {count} times consecutively ('{matched_str}')")

    # 2. Repeated multi-character substrings / periodic cycles (e.g., 'abab', 'abcabc')
    lower_pwd = password.lower()
    length = len(lower_pwd)
    # Check substring lengths from 2 to length // 2
    for chunk_len in range(2, (length // 2) + 1):
        for start_pos in range(length - (2 * chunk_len) + 1):
            chunk = lower_pwd[start_pos:start_pos + chunk_len]
            # See how many times this chunk repeats consecutively
            count = 1
            idx = start_pos + chunk_len
            while idx + chunk_len <= length and lower_pwd[idx:idx + chunk_len] == chunk:
                count += 1
                idx += chunk_len

            if count >= 2:
                # Avoid duplicates or sub-chunks already recorded
                full_rep = chunk * count
                if not any(r["pattern"] == chunk and r["start"] == start_pos for r in repeated_substrings):
                    repeated_substrings.append({
                        "pattern": chunk,
                        "count": count,
                        "full_match": full_rep,
                        "start": start_pos
                    })
                    sub_penalty = min(15, count * 4)
                    penalty += sub_penalty
                    details.append(f"Cyclic repeated substring '{chunk}' repeated {count} times")

    # 3. Overall repetition density: if 1 or 2 unique characters make up 70%+ of length
    unique_count = len(set(lower_pwd))
    if length >= 6 and unique_count <= 2:
        penalty += 15
        details.append(f"Extremely low unique character count ({unique_count} distinct characters across {length} characters)")

    penalty = min(30, penalty)
    has_rep = len(repeated_chars) > 0 or len(repeated_substrings) > 0 or (length >= 6 and unique_count <= 2)

    return {
        "has_repetition": has_rep,
        "repeated_chars": repeated_chars,
        "repeated_substrings": repeated_substrings,
        "max_consecutive_count": max_consecutive,
        "penalty": penalty,
        "details": details
    }
