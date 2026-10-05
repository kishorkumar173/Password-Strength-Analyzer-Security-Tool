"""
Configuration settings for Password Strength Analyzer & Security Suggestion Tool.
Designed with defensive security principles:
- Zero credential logging
- In-memory ephemeral processing
- Safe aggregate analytics
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"
KEYBOARD_LAYOUTS_FILE = DATA_DIR / "keyboard_layouts.json"

# Server Settings
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 5000))
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

# Security & Constraints
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 1
ENABLE_ANALYTICS = os.environ.get("ENABLE_ANALYTICS", "True").lower() == "true"
DATABASE_PATH = BASE_DIR / "backend" / "analytics.db"

# Strength Classifications
TIER_VERY_WEAK = "VERY WEAK"
TIER_WEAK = "WEAK"
TIER_MODERATE = "MODERATE"
TIER_STRONG = "STRONG"
TIER_VERY_STRONG = "VERY STRONG"

SCORE_THRESHOLDS = {
    TIER_VERY_WEAK: (0, 20),
    TIER_WEAK: (21, 40),
    TIER_MODERATE: (41, 60),
    TIER_STRONG: (61, 80),
    TIER_VERY_STRONG: (81, 100),
}
