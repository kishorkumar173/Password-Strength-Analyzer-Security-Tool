"""
Sequence Detection Service.
Identifies ascending and descending sequential patterns in numeric and alphabetical sequences.
Predictable sequences drastically reduce the effective search space for automated tools.
"""

from typing import Dict, Any, List


def detect_sequences(password: str, min_length: int = 3) -> Dict[str, Any]:
    """
    Detects contiguous ascending or descending sequences of numbers or letters.
    Examples:
      - Numeric: '1234', '5678', '9876', '4321'
      - Alpha:   'abcd', 'bcde', 'dcba', 'zyxw'

    Args:
      password: The candidate password.
      min_length: Minimum length of run to consider a sequence (default: 3).

    Returns:
      Dict with has_sequence, sequences_found, penalty, and details.
    """
    if not password or len(password) < min_length:
        return {
            "has_sequence": False,
            "sequences_found": [],
            "penalty": 0,
            "details": []
        }

    sequences_found: List[Dict[str, Any]] = []
    total_penalty = 0

    # 1. Numeric Sequences
    i = 0
    while i < len(password):
        if password[i].isdigit():
            # Check ascending
            asc_run = [password[i]]
            j = i + 1
            while j < len(password) and password[j].isdigit():
                if int(password[j]) == (int(asc_run[-1]) + 1) % 10:
                    asc_run.append(password[j])
                    j += 1
                else:
                    break
            if len(asc_run) >= min_length:
                seq_str = "".join(asc_run)
                sequences_found.append({
                    "type": "Numeric Ascending",
                    "pattern": seq_str,
                    "length": len(seq_str),
                    "start": i
                })
                total_penalty += min(20, len(seq_str) * 4)
                i = j
                continue

            # Check descending
            desc_run = [password[i]]
            j = i + 1
            while j < len(password) and password[j].isdigit():
                if int(password[j]) == (int(desc_run[-1]) - 1) % 10:
                    desc_run.append(password[j])
                    j += 1
                else:
                    break
            if len(desc_run) >= min_length:
                seq_str = "".join(desc_run)
                sequences_found.append({
                    "type": "Numeric Descending",
                    "pattern": seq_str,
                    "length": len(seq_str),
                    "start": i
                })
                total_penalty += min(20, len(seq_str) * 4)
                i = j
                continue
        i += 1

    # 2. Alphabetical Sequences (Case-insensitive)
    lower_pwd = password.lower()
    i = 0
    while i < len(lower_pwd):
        if lower_pwd[i].isalpha():
            # Check ascending alpha
            asc_alpha = [lower_pwd[i]]
            j = i + 1
            while j < len(lower_pwd) and lower_pwd[j].isalpha():
                if ord(lower_pwd[j]) - ord(asc_alpha[-1]) == 1:
                    asc_alpha.append(lower_pwd[j])
                    j += 1
                else:
                    break
            if len(asc_alpha) >= min_length:
                seq_str = "".join(asc_alpha)
                sequences_found.append({
                    "type": "Alphabetical Ascending",
                    "pattern": seq_str,
                    "length": len(seq_str),
                    "start": i
                })
                total_penalty += min(20, len(seq_str) * 4)
                i = j
                continue

            # Check descending alpha
            desc_alpha = [lower_pwd[i]]
            j = i + 1
            while j < len(lower_pwd) and lower_pwd[j].isalpha():
                if ord(desc_alpha[-1]) - ord(lower_pwd[j]) == 1:
                    desc_alpha.append(lower_pwd[j])
                    j += 1
                else:
                    break
            if len(desc_alpha) >= min_length:
                seq_str = "".join(desc_alpha)
                sequences_found.append({
                    "type": "Alphabetical Descending",
                    "pattern": seq_str,
                    "length": len(seq_str),
                    "start": i
                })
                total_penalty += min(20, len(seq_str) * 4)
                i = j
                continue
        i += 1

    # Cap sequence penalty to 25
    total_penalty = min(25, total_penalty)

    return {
        "has_sequence": len(sequences_found) > 0,
        "sequences_found": sequences_found,
        "penalty": total_penalty,
        "details": [f"{s['type']} pattern '{s['pattern']}'" for s in sequences_found]
    }
