"""
Password Strength Scoring Engine.
Synthesizes length, character diversity, uniqueness, common-word presence,
sequences, repetitions, keyboard patterns, and predictable structures into a 0-100 score.
Maps score to clear industry-oriented strength tiers:
  - VERY WEAK (0-20)
  - WEAK (21-40)
  - MODERATE (41-60)
  - STRONG (61-80)
  - VERY STRONG (81-100)
"""

from typing import Dict, Any, List
from backend.config import (
    TIER_VERY_WEAK,
    TIER_WEAK,
    TIER_MODERATE,
    TIER_STRONG,
    TIER_VERY_STRONG,
    SCORE_THRESHOLDS
)


def compute_strength_score(
    length_result: Dict[str, Any],
    char_result: Dict[str, Any],
    common_result: Dict[str, Any],
    sequence_result: Dict[str, Any],
    keyboard_result: Dict[str, Any],
    repetition_result: Dict[str, Any],
    structure_result: Dict[str, Any],
    context_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes composite password strength score (0-100) and classification.

    Returns:
      Dict with score, classification, breakdown (positive additions and deductions),
      color_code, and summary.
    """
    length = length_result.get("length", 0)

    if length == 0:
        return {
            "score": 0,
            "classification": TIER_VERY_WEAK,
            "color": "#ef4444",
            "breakdown": {
                "base_score": 0,
                "additions": [],
                "deductions": []
            },
            "summary": "No password provided."
        }

    additions: List[Dict[str, Any]] = []
    deductions: List[Dict[str, Any]] = []

    # 1. POSITIVE CONTRIBUTIONS (Max potential: ~100)
    # Length contribution (up to 35)
    len_score = length_result.get("score_contribution", 0)
    additions.append({
        "category": "Password Length",
        "points": len_score,
        "detail": f"{length} characters ({length_result.get('band')})"
    })

    # Character Diversity (up to 15)
    variety_score = char_result.get("variety_score", 0)
    additions.append({
        "category": "Character Diversity",
        "points": variety_score,
        "detail": f"{char_result.get('character_type_count')} character types detected"
    })

    # Uniqueness Ratio (up to 10)
    uniq_score = char_result.get("uniqueness_score", 0)
    additions.append({
        "category": "Character Uniqueness",
        "points": uniq_score,
        "detail": f"{char_result.get('unique_character_ratio', 0):.0%} unique characters"
    })

    # Pattern Resistance Baseline (up to 20 if free of simple sequence/keyboard walks)
    pattern_baseline = 20
    if sequence_result.get("has_sequence") or keyboard_result.get("has_keyboard_pattern"):
        pattern_baseline = 5
    additions.append({
        "category": "Structural Complexity",
        "points": pattern_baseline,
        "detail": "Absence of basic walk or sequential crutches" if pattern_baseline == 20 else "Compromised by sequential/walk patterns"
    })

    # Non-Common Password Baseline (up to 10)
    non_common_bonus = 0 if common_result.get("is_common") else 10
    additions.append({
        "category": "Dictionary Resistance",
        "points": non_common_bonus,
        "detail": "Not present in common password dataset" if non_common_bonus > 0 else "Found in common wordlist"
    })

    # Bonus Unpredictability (Length >= 18 with high uniqueness gets up to 10 extra)
    extra_bonus = 0
    if length >= 18 and char_result.get("unique_character_ratio", 0) >= 0.7:
        extra_bonus = 10
    elif length >= 14 and char_result.get("character_type_count", 0) >= 3:
        extra_bonus = 5
    if extra_bonus > 0:
        additions.append({
            "category": "High Entropy / Length Bonus",
            "points": extra_bonus,
            "detail": "Extended length combined with varied characters"
        })

    raw_positive = sum(a["points"] for a in additions)

    # 2. DEDUCTIONS / PENALTIES
    # Common password penalty
    if common_result.get("is_common"):
        pen = common_result.get("penalty", 30)
        deductions.append({
            "category": "Common Password Match",
            "points": -pen,
            "detail": common_result.get("message", "Known common password")
        })

    # Keyboard pattern penalty
    if keyboard_result.get("has_keyboard_pattern"):
        pen = keyboard_result.get("penalty", 15)
        deductions.append({
            "category": "Keyboard Walk Pattern",
            "points": -pen,
            "detail": ", ".join(keyboard_result.get("details", []))
        })

    # Sequence penalty
    if sequence_result.get("has_sequence"):
        pen = sequence_result.get("penalty", 15)
        deductions.append({
            "category": "Sequential Characters",
            "points": -pen,
            "detail": ", ".join(sequence_result.get("details", []))
        })

    # Repetition penalty
    if repetition_result.get("has_repetition"):
        pen = repetition_result.get("penalty", 15)
        deductions.append({
            "category": "Repeated Characters/Substrings",
            "points": -pen,
            "detail": ", ".join(repetition_result.get("details", []))
        })

    # Predictable structure (TitleCase word + numbers + symbol, Year)
    if structure_result.get("has_predictable_structure"):
        pen = structure_result.get("penalty", 15)
        deductions.append({
            "category": "Predictable Formula / Year",
            "points": -pen,
            "detail": ", ".join(structure_result.get("details", []))
        })

    # Context overlap penalty
    if context_result.get("has_context_overlap"):
        pen = context_result.get("penalty", 20)
        deductions.append({
            "category": "Personal Context Overlap",
            "points": -pen,
            "detail": context_result.get("message", "Personal info found")
        })

    raw_negative = sum(abs(d["points"]) for d in deductions)

    # Calculate final clamped score
    calculated_score = max(0, min(100, raw_positive - raw_negative))

    # Strict hard caps for critical flaws:
    # 1. If exact common password, cap score at 15
    if common_result.get("is_common") and not common_result.get("is_leetspeak"):
        calculated_score = min(calculated_score, 15)
    # 2. If length < 8, cap score at 25
    if length < 8:
        calculated_score = min(calculated_score, 25)
    # 3. If single repeated character throughout (e.g. 'aaaaaaaa'), cap at 20
    if char_result.get("unique_character_count", 0) <= 1:
        calculated_score = min(calculated_score, 15)

    # Classification Mapping
    classification = TIER_VERY_WEAK
    color = "#ef4444"  # Red

    if calculated_score <= 20:
        classification = TIER_VERY_WEAK
        color = "#ef4444"  # Red
    elif 21 <= calculated_score <= 40:
        classification = TIER_WEAK
        color = "#f97316"  # Orange
    elif 41 <= calculated_score <= 60:
        classification = TIER_MODERATE
        color = "#eab308"  # Yellow
    elif 61 <= calculated_score <= 80:
        classification = TIER_STRONG
        color = "#3b82f6"  # Blue
    else:
        classification = TIER_VERY_STRONG
        color = "#10b981"  # Emerald Green

    summary = (
        f"Password achieved a score of {calculated_score}/100 and is classified as {classification}. "
        f"Evaluated against length, character dispersion, and structural predictability."
    )

    return {
        "score": calculated_score,
        "classification": classification,
        "color": color,
        "breakdown": {
            "positive_total": raw_positive,
            "deductions_total": raw_negative,
            "additions": additions,
            "deductions": deductions
        },
        "summary": summary
    }
