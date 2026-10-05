"""
Educational Password Hashing Demonstration Service.
Demonstrates:
  1. Plaintext vs One-Way Hash
  2. The role of Cryptographic Salt (mitigating Rainbow Tables)
  3. Key Stretching and Work Factor (PBKDF2-HMAC-SHA256 / bcrypt)
  4. Constant-time verification to prevent timing side-channel attacks
Strictly for educational demonstration with synthetic passwords.
DOES NOT persist any entered credentials.
"""

import os
import hmac
import hashlib
import time
from typing import Dict, Any

# Try importing bcrypt if available, else standard library PBKDF2
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


def demonstrate_hashing(password: str, iterations: int = 100000) -> Dict[str, Any]:
    """
    Demonstrates the cryptographic pipeline:
      Plaintext + Cryptographic Salt -> Key Stretching Function -> Storage Representation

    Educational Points:
      - MD5 / SHA-256 are general-purpose digests designed for high-throughput checksums.
        Attackers can compute billions of SHA-256 hashes per second on a single GPU.
      - Password hashing functions (Argon2id, bcrypt, PBKDF2, scrypt) are deliberately slow
        and configurable with work factors to make brute-force economically prohibitive.
      - Salt ensures two users with the exact same password produce completely distinct hashes.

    Returns:
      Educational breakdown dictionary.
    """
    if not password:
        password = "SyntheticDemoPassword42!"

    # 1. Generate 16 bytes of cryptographically secure random salt
    salt = os.urandom(16)
    salt_hex = salt.hex()

    # 2. Fast Unsalted Hash (Bad Practice demonstration - SHA256)
    fast_start = time.perf_counter()
    fast_sha256 = hashlib.sha256(password.encode("utf-8")).hexdigest()
    fast_duration_ms = round((time.perf_counter() - fast_start) * 1000, 4)

    # 3. Slow Salted Key-Stretched Hash (Standard Practice - PBKDF2-HMAC-SHA256)
    slow_start = time.perf_counter()
    stretched_derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=32
    )
    slow_duration_ms = round((time.perf_counter() - slow_start) * 1000, 2)
    stretched_hex = stretched_derived.hex()

    # Formatted storage string: algorithm$iterations$salt$hash
    storage_string = f"pbkdf2:sha256:{iterations}${salt_hex}${stretched_hex}"

    # 4. Optional bcrypt demonstration
    bcrypt_representation = None
    if BCRYPT_AVAILABLE:
        try:
            b_salt = bcrypt.gensalt(rounds=12)
            b_hash = bcrypt.hashpw(password.encode("utf-8"), b_salt)
            bcrypt_representation = b_hash.decode("utf-8")
        except Exception:
            bcrypt_representation = "bcrypt available but encountered runtime error"
    else:
        bcrypt_representation = "$2b$12$e8YQ3f4rZ... (bcrypt optional package not installed)"

    return {
        "input_label": "Demo Synthetic Input",
        "input_length": len(password),
        "salt_hex": salt_hex,
        "salt_size_bytes": 16,
        "iterations": iterations,
        "fast_hash": {
            "algorithm": "SHA-256 (Unsalted - Unsafe for storage)",
            "output": fast_sha256,
            "duration_ms": fast_duration_ms,
            "why_unsafe": "GPU can test over 10 billion unsalted SHA-256 hashes per second."
        },
        "slow_hash": {
            "algorithm": "PBKDF2-HMAC-SHA256 (Salted + Key-Stretched)",
            "output": storage_string,
            "duration_ms": slow_duration_ms,
            "why_safe": f"Forces {iterations:,} iterative rounds per guess, bottlenecking GPU acceleration."
        },
        "bcrypt_equivalent": bcrypt_representation,
        "modern_gold_standard": "Argon2id (Winner of Password Hashing Competition; resistant to GPU/ASIC memory optimization)",
        "educational_takeaway": (
            "Never store plaintext passwords or fast single-iteration hashes (MD5/SHA1/SHA256). "
            "Always use slow, memory-hard, salted key-derivation functions (Argon2id or bcrypt)."
        )
    }


def verify_demo_password(password: str, storage_string: str) -> Dict[str, Any]:
    """
    Demonstrates constant-time password verification using hmac.compare_digest.
    """
    try:
        parts = storage_string.split("$")
        algo_info = parts[0]  # pbkdf2:sha256:iterations
        salt_hex = parts[1]
        expected_hash = parts[2]

        iterations = int(algo_info.split(":")[2])
        salt = bytes.fromhex(salt_hex)

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32
        )
        calculated_hash = derived.hex()

        # Constant-time comparison to prevent timing attacks
        matches = hmac.compare_digest(calculated_hash, expected_hash)

        return {
            "verified": matches,
            "method": "hmac.compare_digest (Constant-Time Side-Channel Resistant)",
            "message": "Password successfully verified against stored hash." if matches else "Verification failed: Hash mismatch."
        }
    except Exception as e:
        return {
            "verified": False,
            "method": "verification_error",
            "message": f"Malformed storage hash string: {str(e)}"
        }
