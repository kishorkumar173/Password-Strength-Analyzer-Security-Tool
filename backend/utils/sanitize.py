"""
Security & Sanitization Utilities.
Provides defensive helper functions:
  - Masking utilities (ensuring strings are never accidentally logged)
  - Input truncation to defend against memory exhaustion DoS attacks
"""

import re


def sanitize_text(text: str, max_len: int = 256) -> str:
    """Safely bounds input strings to prevent resource exhaustion attacks."""
    if not text:
        return ""
    return str(text)[:max_len].strip()


def mask_sensitive(text: str) -> str:
    """
    Returns an obfuscated mask string (e.g. '••••••••') so sensitive data
    never enters logs or error traces.
    """
    if not text:
        return ""
    return "•" * min(len(text), 16)
