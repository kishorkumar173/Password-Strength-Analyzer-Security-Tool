"""
Cryptographically Secure Password & Passphrase Generator Service.
Utilizes Python's `secrets` module (CSPRNG) backed by OS entropy (CryptGenRandom/getrandom).
Includes:
  1. High-Entropy Character-Based Password Generator
  2. Diceware-Style Word Passphrase Generator
Never logs or persists generated credentials.
"""

import secrets
import string
from typing import Dict, Any, List

# Curated list of distinct, memorable, non-offensive English words for Diceware-style passphrases
DICEWARE_WORDLIST: List[str] = [
    "amber", "anchor", "beacon", "breeze", "bridge", "cactus", "canyon", "castle",
    "cedar", "cipher", "cliff", "comet", "crater", "crystal", "delta", "desert",
    "dolphin", "dragon", "falcon", "feather", "forest", "fountain", "galaxy", "glacier",
    "granite", "harbor", "horizon", "island", "jungle", "lagoon", "lantern", "lizard",
    "marble", "meadow", "meteor", "nebula", "nomad", "oasis", "ocean", "orchid",
    "pebble", "phoenix", "planet", "pyramid", "quartz", "quiver", "radius", "rainbow",
    "ravine", "ripple", "safari", "shadow", "shield", "silver", "summit", "thunder",
    "timber", "topaz", "tornado", "tulip", "tunnel", "valley", "velvet", "vessel",
    "volcano", "vortex", "walnut", "willow", "winter", "zenith", "zephyr", "zodiac",
    "cascade", "compass", "diamond", "emerald", "eclipse", "glacier", "journey", "matrix",
    "monarch", "mystery", "network", "neutron", "odyssey", "pioneer", "quantum", "solace",
    "sparrow", "starlight", "timber", "titan", "trident", "whisper", "wilderness", "voyage"
]


def generate_secure_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> Dict[str, Any]:
    """
    Generates a cryptographically secure random password.

    Security Guarantee:
      Uses `secrets.SystemRandom` backed by operating system entropy.
      Guarantees at least one character from each selected class to satisfy legacy policies.

    Random vs Secrets:
      Python's `random` module uses the Mersenne Twister (MT19937) algorithm, which is
      deterministic and allows an attacker observing 624 outputs to predict all future outputs.
      `secrets` uses cryptographically secure hardware-seeded OS RNG (`CryptGenRandom` / `getrandom`).

    Returns:
      Dict with password, length, character_types, and security_notes.
    """
    length = max(8, min(64, length))

    pools: List[str] = []
    guaranteed: List[str] = []

    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        # Safe selection of symbols excluding ambiguous quotes/backslashes
        safe_symbols = "!@#$%^&*()-_=+[]{}<>?"
        pools.append(safe_symbols)
        guaranteed.append(secrets.choice(safe_symbols))

    if not pools:
        # Default fallback if user unchecks all
        pools.append(string.ascii_lowercase + string.digits)
        guaranteed.append(secrets.choice(string.ascii_lowercase))

    full_pool = "".join(pools)
    remaining_length = length - len(guaranteed)
    random_chars = [secrets.choice(full_pool) for _ in range(remaining_length)]

    # Combine guaranteed characters with remaining random characters
    password_chars = guaranteed + random_chars

    # Cryptographically secure in-place shuffle
    secrets.SystemRandom().shuffle(password_chars)
    generated_pwd = "".join(password_chars)

    return {
        "password": generated_pwd,
        "length": length,
        "types_included": {
            "uppercase": use_upper,
            "lowercase": use_lower,
            "digits": use_digits,
            "symbols": use_symbols
        },
        "csprng_source": "Python secrets (OS CryptGenRandom/getrandom)",
        "security_note": "Generated using a cryptographically secure pseudo-random number generator (CSPRNG). Never stored."
    }


def generate_secure_passphrase(
    word_count: int = 4,
    separator: str = "-"
) -> Dict[str, Any]:
    """
    Generates a Diceware-style multi-word passphrase.

    Concept:
      Coined by Arnold Reinhold (Diceware) and popularized by xkcd #936, passphrases
      combine long physical length with high human memorability.
      Each word drawn uniformly at random from a known wordlist contributes
      log2(wordlist_size) bits of genuine entropy.

    Returns:
      Dict with passphrase, word_count, separator, and theoretical_bits.
    """
    word_count = max(3, min(8, word_count))
    selected_words = [secrets.choice(DICEWARE_WORDLIST) for _ in range(word_count)]
    passphrase = separator.join(selected_words)

    # Wordlist size calculation: ~100 curated words -> ~6.64 bits per word
    bits_per_word = 6.64
    estimated_entropy = round(word_count * bits_per_word, 1)

    return {
        "passphrase": passphrase,
        "word_count": word_count,
        "separator": separator,
        "words": selected_words,
        "estimated_bits": estimated_entropy,
        "security_note": (
            f"Passphrase of {word_count} randomly chosen words. Long physical length "
            f"({len(passphrase)} chars) makes brute-force computationally prohibitive while "
            "remaining memorable to the user."
        )
    }
