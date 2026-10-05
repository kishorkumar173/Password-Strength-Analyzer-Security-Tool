"""
Common Password Detection Service.
Checks candidate password against local educational list of common passwords,
including leetspeak and case-normalized variations.
Strictly local, safe, and privacy-preserving.
"""

from pathlib import Path
from typing import Dict, Any, Set
from backend.config import COMMON_PASSWORDS_FILE


class CommonPasswordChecker:
    def __init__(self, dataset_path: Path = COMMON_PASSWORDS_FILE):
        self.dataset_path = dataset_path
        self.common_passwords: Set[str] = set()
        self._load_dataset()

    def _load_dataset(self) -> None:
        """Loads common passwords into memory from local text file."""
        if not self.dataset_path.exists():
            # Fallback embedded set if file is missing
            self.common_passwords = {
                "password", "password123", "123456", "12345678", "qwerty",
                "letmein", "welcome", "admin", "admin123", "root", "root123",
                "pass1234", "p@ssword", "iloveyou", "monkey", "dragon"
            }
            return

        try:
            with open(self.dataset_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.common_passwords.add(line.lower())
        except Exception:
            self.common_passwords = {"password", "123456", "admin", "welcome", "qwerty"}

    @staticmethod
    def _normalize_leetspeak(text: str) -> str:
        """Converts common leetspeak substitutions back to standard alphabetical characters."""
        leet_map = {
            '@': 'a',
            '4': 'a',
            '8': 'b',
            '3': 'e',
            '1': 'i',
            '!': 'i',
            '0': 'o',
            '$': 's',
            '5': 's',
            '7': 't',
            '+': 't'
        }
        normalized = text.lower()
        for leet_char, standard_char in leet_map.items():
            normalized = normalized.replace(leet_char, standard_char)
        return normalized

    def check(self, password: str) -> Dict[str, Any]:
        """
        Evaluates whether the password matches or contains common dictionary passwords.

        Returns:
          Dict with is_common, matched_pattern, is_leetspeak, penalty, and message.
        """
        if not password:
            return {
                "is_common": False,
                "matched_pattern": None,
                "is_leetspeak": False,
                "penalty": 0,
                "message": "Empty password."
            }

        lower_pwd = password.lower().strip()

        # 1. Direct exact match
        if lower_pwd in self.common_passwords:
            has_leet_chars = any(c in "@4831!0$57+" for c in lower_pwd)
            return {
                "is_common": True,
                "matched_pattern": lower_pwd,
                "is_leetspeak": has_leet_chars,
                "penalty": 40,
                "severity": "CRITICAL",
                "message": "Your password matches a commonly used password pattern and should not be used."
            }

        # 2. Leetspeak transformed match
        normalized_leet = self._normalize_leetspeak(lower_pwd)
        if normalized_leet in self.common_passwords:
            return {
                "is_common": True,
                "matched_pattern": normalized_leet,
                "is_leetspeak": True,
                "penalty": 35,
                "severity": "HIGH",
                "message": "Your password matches a commonly used password with predictable character substitution (leetspeak)."
            }

        # 3. Substring check for major common words (min length 4 to avoid false positives)
        for common in self.common_passwords:
            if len(common) >= 5 and (common in lower_pwd or common in normalized_leet):
                return {
                    "is_common": True,
                    "matched_pattern": common,
                    "is_leetspeak": common in normalized_leet and common not in lower_pwd,
                    "penalty": 25,
                    "severity": "HIGH",
                    "message": f"Your password contains the well-known common term or dictionary pattern '{common}'."
                }

        return {
            "is_common": False,
            "matched_pattern": None,
            "is_leetspeak": False,
            "penalty": 0,
            "severity": "NONE",
            "message": "No match found in common password dictionary."
        }


# Singleton instance
_checker_instance = None


def is_common_password(password: str) -> Dict[str, Any]:
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = CommonPasswordChecker()
    return _checker_instance.check(password)
