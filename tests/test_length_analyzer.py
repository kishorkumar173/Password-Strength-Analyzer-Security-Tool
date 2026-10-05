"""Unit tests for Length Analyzer."""
from backend.services.length_analyzer import analyze_length

def test_empty_length():
    res = analyze_length("")
    assert res["length"] == 0
    assert res["band"] == "Empty"

def test_short_length():
    res = analyze_length("123456")
    assert res["length"] == 6
    assert res["band"] == "Very Short"
    assert res["score_contribution"] == 5

def test_medium_length():
    res = analyze_length("standardpass")
    assert res["length"] == 12
    assert res["band"] == "Better Length"
    assert res["score_contribution"] == 25

def test_strong_length():
    res = analyze_length("this-is-a-very-long-passphrase-example")
    assert res["length"] > 16
    assert res["band"] == "Strong Length Contribution"
    assert res["score_contribution"] == 35
