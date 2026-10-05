"""
Keyboard Pattern Detection Service.
Identifies common keyboard walks (horizontal, vertical, diagonal) across standard QWERTY layout.
Keyboard walks are among the first mutations tested by dictionary attack tools.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
from backend.config import KEYBOARD_LAYOUTS_FILE


class KeyboardDetector:
    def __init__(self, layouts_path: Path = KEYBOARD_LAYOUTS_FILE):
        self.layouts_path = layouts_path
        self.rows: List[str] = []
        self.common_walks: List[str] = []
        self._load_layouts()

    def _load_layouts(self) -> None:
        """Loads keyboard layouts and patterns from JSON file."""
        if not self.layouts_path.exists():
            self.rows = [
                "qwertyuiop",
                "asdfghjkl",
                "zxcvbnm",
                "1234567890"
            ]
            self.common_walks = ["qwerty", "asdf", "zxcv", "1qaz", "2wsx"]
            return

        try:
            with open(self.layouts_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.rows = [r.lower() for r in data.get("qwerty_rows", [])]
                self.common_walks = [w.lower() for w in data.get("common_walks", [])]
        except Exception:
            self.rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
            self.common_walks = ["qwerty", "asdf", "zxcv"]

    def detect(self, password: str, min_length: int = 4) -> Dict[str, Any]:
        """
        Detects keyboard walk patterns.

        Args:
          password: Input password.
          min_length: Minimum walk segment to flag (default: 4).

        Returns:
          Dict containing detection status, detected walks, penalty, and descriptions.
        """
        if not password or len(password) < min_length:
            return {
                "has_keyboard_pattern": False,
                "patterns_found": [],
                "penalty": 0,
                "details": []
            }

        lower_pwd = password.lower()
        patterns_found: List[Dict[str, Any]] = []

        # 1. Check against known common walks list
        for walk in self.common_walks:
            if walk in lower_pwd:
                patterns_found.append({
                    "pattern": walk,
                    "type": "Standard Common Walk",
                    "start": lower_pwd.find(walk)
                })

        # 2. Check dynamic horizontal keyboard row sequences (forward and backward)
        for row in self.rows:
            # Forward row slices
            for length in range(min_length, min(len(row) + 1, 10)):
                for start_idx in range(len(row) - length + 1):
                    slice_fwd = row[start_idx:start_idx + length]
                    if slice_fwd in lower_pwd and not any(p["pattern"] == slice_fwd for p in patterns_found):
                        patterns_found.append({
                            "pattern": slice_fwd,
                            "type": "Horizontal Row Walk (Forward)",
                            "start": lower_pwd.find(slice_fwd)
                        })
                    # Reverse row slices
                    slice_rev = slice_fwd[::-1]
                    if slice_rev in lower_pwd and not any(p["pattern"] == slice_rev for p in patterns_found):
                        patterns_found.append({
                            "pattern": slice_rev,
                            "type": "Horizontal Row Walk (Reverse)",
                            "start": lower_pwd.find(slice_rev)
                        })

        # Calculate penalty
        penalty = min(25, len(patterns_found) * 12)

        return {
            "has_keyboard_pattern": len(patterns_found) > 0,
            "patterns_found": patterns_found,
            "penalty": penalty,
            "details": [f"{p['type']}: '{p['pattern']}'" for p in patterns_found]
        }


# Singleton instance
_detector_instance = None


def detect_keyboard_patterns(password: str) -> Dict[str, Any]:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = KeyboardDetector()
    return _detector_instance.detect(password)
