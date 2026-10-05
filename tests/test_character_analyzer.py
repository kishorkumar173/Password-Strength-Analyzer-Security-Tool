"""Unit tests for Character Diversity and Sequence Detector."""
from backend.services.character_analyzer import analyze_characters
from backend.services.sequence_detector import detect_sequences

def test_character_analyzer_diversity():
    res = analyze_characters("Abc#123")
    assert res["has_lowercase"] is True
    assert res["has_uppercase"] is True
    assert res["has_digits"] is True
    assert res["has_symbols"] is True
    assert res["character_type_count"] == 4
    assert res["estimated_pool_size"] == 26 + 26 + 10 + 33

def test_sequence_detector_numeric():
    res_asc = detect_sequences("pass1234word")
    assert res_asc["has_sequence"] is True
    assert any(s["type"] == "Numeric Ascending" for s in res_asc["sequences_found"])

    res_desc = detect_sequences("pass4321word")
    assert res_desc["has_sequence"] is True
    assert any(s["type"] == "Numeric Descending" for s in res_desc["sequences_found"])

def test_sequence_detector_alpha():
    res_alpha = detect_sequences("passabcdword")
    assert res_alpha["has_sequence"] is True
    assert any(s["type"] == "Alphabetical Ascending" for s in res_alpha["sequences_found"])
