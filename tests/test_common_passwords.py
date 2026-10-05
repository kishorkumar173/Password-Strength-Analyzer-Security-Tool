"""Unit tests for Keyboard Patterns and Common Passwords."""
from backend.services.keyboard_detector import detect_keyboard_patterns
from backend.services.common_password_checker import is_common_password

def test_keyboard_walk_qwerty():
    res = detect_keyboard_patterns("myqwerty123")
    assert res["has_keyboard_pattern"] is True
    assert any("qwerty" in p["pattern"] for p in res["patterns_found"])

def test_keyboard_walk_asdf():
    res = detect_keyboard_patterns("user_asdfgh_key")
    assert res["has_keyboard_pattern"] is True

def test_common_password_exact():
    res = is_common_password("password123")
    assert res["is_common"] is True
    assert res["severity"] == "CRITICAL"

def test_common_password_leetspeak():
    res = is_common_password("p@ssword")
    assert res["is_common"] is True
    assert res["is_leetspeak"] is True

def test_uncommon_password():
    res = is_common_password("Xy9#kL2$vM8@zQ4w")
    assert res["is_common"] is False
