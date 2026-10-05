"""
Entropy Estimation Service.
Calculates both theoretical Shannon/pool entropy and pattern-adjusted effective entropy.
Provides clear educational commentary on why theoretical entropy alone is misleading
when applied to non-random human passwords.
"""

import math
from typing import Dict, Any


def estimate_theoretical_entropy(
    password: str,
    pool_size: int,
    pattern_penalties: int = 0
) -> Dict[str, Any]:
    """
    Computes information entropy metrics for a password.

    Formula:
      Theoretical Entropy (bits) = L * log2(N)
      where:
        L = password length
        N = size of the character pool the password is drawn from

    Critical Limitation Explained:
      Theoretical entropy assumes every character was chosen via independent,
      identically distributed (IID) uniform random selection.
      Human-generated passwords follow predictable phonetics, keyboard shortcuts,
      and cultural habits, causing 'effective entropy' to be drastically lower.

    Args:
      password: The candidate password.
      pool_size: Estimated alphabet size N.
      pattern_penalties: Aggregated penalty score from pattern detectors.

    Returns:
      Dict with theoretical_bits, effective_bits, pool_size, and educational explanations.
    """
    length = len(password) if password else 0

    if length == 0 or pool_size <= 1:
        return {
            "theoretical_bits": 0.0,
            "effective_bits": 0.0,
            "pool_size": 0,
            "bits_per_character": 0.0,
            "educational_note": "Cannot calculate entropy for empty or single-character pools.",
            "resistance_offline": "Instantaneous (0 seconds)",
            "resistance_online": "Instantaneous (0 seconds)",
            "entropy_rating": "Zero"
        }

    # Standard theoretical pool entropy: L * log2(N)
    bits_per_char = math.log2(pool_size)
    theoretical_bits = round(length * bits_per_char, 1)

    # Effective entropy adjustment based on non-randomness and structural penalties
    # Each 10 points of pattern penalty roughly halves the effective search space (cuts ~3-5 bits)
    penalty_deduction = (pattern_penalties / 100.0) * (theoretical_bits * 0.70)
    effective_bits = max(0.0, round(theoretical_bits - penalty_deduction, 1))

    # Educational resistance estimation (Hypothetical offline GPU rig @ 10^10 hashes/sec vs online rate limit)
    # 2^bits combinations
    if effective_bits < 28:
        rating = "Extremely Weak"
        resistance_offline = "Less than 1 second (Trivial offline dictionary/brute-force)"
        resistance_online = "Vulnerable to basic online spraying"
    elif effective_bits < 45:
        rating = "Weak"
        resistance_offline = "Few seconds to several minutes offline"
        resistance_online = "Moderately resistant to blind online guesses, vulnerable to targeted lists"
    elif effective_bits < 65:
        rating = "Moderate"
        resistance_offline = "Days to several months against offline cluster"
        resistance_online = "Highly resistant to online guessing (if rate limits exist)"
    elif effective_bits < 80:
        rating = "Strong"
        resistance_offline = "Centuries against typical offline cracking clusters"
        resistance_online = "Practically unguessable online"
    else:
        rating = "Very Strong"
        resistance_offline = "Astronomical timeframes (Exceeds millions of years)"
        resistance_online = "Immune to brute-force guessing"

    disclaimer = (
        "Educational estimate only. Real-world cracking resistance depends on the attacker's "
        "hardware, whether the attack is offline or online, the slow-hashing algorithm employed "
        "(e.g., Argon2id vs fast MD5), and whether breach dictionaries are leveraged."
    )

    return {
        "theoretical_bits": theoretical_bits,
        "effective_bits": effective_bits,
        "pool_size": pool_size,
        "bits_per_character": round(bits_per_char, 2),
        "entropy_rating": rating,
        "resistance_offline": resistance_offline,
        "resistance_online": resistance_online,
        "disclaimer": disclaimer,
        "educational_note": (
            f"A theoretical entropy of {theoretical_bits} bits assumes pure machine randomness. "
            f"Factoring in human habits and predictable patterns, the estimated effective entropy "
            f"is approximately {effective_bits} bits."
        )
    }
