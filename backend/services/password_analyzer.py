"""
Master Password Analysis Engine.
Orchestrates modular analyzers:
  - Length Analysis
  - Character Variety & Uniqueness
  - Common Password & Dictionary Matching
  - Sequential Pattern Detection
  - Keyboard Pattern / Walk Detection
  - Repetition & Substring Cycle Detection
  - Predictable Structure (Word+Number, Year, Classic Form) Detection
  - Optional Personal Context Overlap Checking
  - Information Entropy Estimation (Theoretical & Effective)
  - Composite Strength Scoring & Classification
  - Prioritized Security Suggestion Generation

STRICT DEFENSIVE RULES:
  - NEVER logs the submitted password.
  - NEVER persists plaintext passwords.
  - NEVER includes the password in error traces or response payloads.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.services.length_analyzer import analyze_length
from backend.services.character_analyzer import analyze_characters
from backend.services.common_password_checker import is_common_password
from backend.services.sequence_detector import detect_sequences
from backend.services.keyboard_detector import detect_keyboard_patterns
from backend.services.repetition_detector import detect_repetition
from backend.services.predictable_structure_detector import detect_predictable_structure
from backend.services.context_checker import check_personal_context
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.scoring_engine import compute_strength_score
from backend.services.suggestion_engine import generate_suggestions


def analyze_password(
    password: str,
    first_name: Optional[str] = None,
    birth_year: Optional[str] = None,
    organization: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes in-memory, zero-retention multi-factor password strength evaluation.

    Args:
      password: Raw password input (processed in memory, never persisted).
      first_name: Optional first name for contextual correlation.
      birth_year: Optional birth year for contextual correlation.
      organization: Optional college/employer name for contextual correlation.

    Returns:
      Comprehensive structured analysis payload.
    """
    if password is None:
        password = ""

    # Truncate input safely if an adversarial payload attempts a DoS with millions of chars
    password = password[:256]

    # 1. Modular Sub-Analysis Passes
    len_res = analyze_length(password)
    char_res = analyze_characters(password)
    common_res = is_common_password(password)
    seq_res = detect_sequences(password)
    key_res = detect_keyboard_patterns(password)
    rep_res = detect_repetition(password)
    struct_res = detect_predictable_structure(password)
    context_res = check_personal_context(password, first_name, birth_year, organization)

    # Calculate aggregate pattern penalties for entropy calibration
    pattern_penalties = (
        common_res.get("penalty", 0) +
        seq_res.get("penalty", 0) +
        key_res.get("penalty", 0) +
        rep_res.get("penalty", 0) +
        struct_res.get("penalty", 0) +
        context_res.get("penalty", 0)
    )

    # 2. Entropy Estimation
    entropy_res = estimate_theoretical_entropy(
        password=password,
        pool_size=char_res.get("estimated_pool_size", 0),
        pattern_penalties=pattern_penalties
    )

    # 3. Composite Scoring & Classification
    score_res = compute_strength_score(
        length_result=len_res,
        char_result=char_res,
        common_result=common_res,
        sequence_result=seq_res,
        keyboard_result=key_res,
        repetition_result=rep_res,
        structure_result=struct_res,
        context_result=context_res
    )

    final_score = score_res["score"]
    classification = score_res["classification"]

    # 4. Generate Actionable Security Suggestions
    suggestions = generate_suggestions(
        length_result=len_res,
        char_result=char_res,
        common_result=common_res,
        sequence_result=seq_res,
        keyboard_result=key_res,
        repetition_result=rep_res,
        structure_result=struct_res,
        context_result=context_res,
        score=final_score
    )

    # 5. Compile Findings List
    findings = []

    # Positive Findings
    if len_res["length"] >= 16:
        findings.append({
            "type": "POSITIVE",
            "severity": "SUCCESS",
            "title": "Strong Length Base",
            "description": f"Length of {len_res['length']} characters provides strong resistance to brute-force."
        })
    elif len_res["length"] >= 12:
        findings.append({
            "type": "POSITIVE",
            "severity": "INFO",
            "title": "Good Length Base",
            "description": f"Length of {len_res['length']} characters satisfies modern baseline guidelines."
        })

    if char_res["character_type_count"] >= 3:
        findings.append({
            "type": "POSITIVE",
            "severity": "SUCCESS",
            "title": "Character Diversity",
            "description": f"Combines {char_res['character_type_count']} distinct character categories."
        })

    if char_res["unique_character_ratio"] >= 0.75 and len_res["length"] >= 8:
        findings.append({
            "type": "POSITIVE",
            "severity": "SUCCESS",
            "title": "High Character Uniqueness",
            "description": f"{char_res['unique_character_ratio']:.0%} of the password consists of distinct characters."
        })

    # Weakness / Warning Findings
    if common_res["is_common"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "CRITICAL",
            "title": "Known Common Password",
            "description": common_res["message"]
        })

    if len_res["length"] < 8 and len_res["length"] > 0:
        findings.append({
            "type": "WEAKNESS",
            "severity": "CRITICAL",
            "title": "Critically Short Length",
            "description": len_res["description"]
        })

    if seq_res["has_sequence"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "HIGH",
            "title": "Predictable Sequence Detected",
            "description": f"Found sequential run: {', '.join(seq_res['details'])}"
        })

    if key_res["has_keyboard_pattern"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "HIGH",
            "title": "Keyboard Pattern Detected",
            "description": f"Found keyboard walk: {', '.join(key_res['details'])}"
        })

    if rep_res["has_repetition"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "MEDIUM",
            "title": "Character / Substring Repetition Detected",
            "description": f"Repetitive patterns found: {', '.join(rep_res['details'][:2])}"
        })

    if struct_res["has_predictable_structure"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "MEDIUM",
            "title": "Predictable Composition Structure",
            "description": f"Structured pattern matched: {', '.join(struct_res['details'])}"
        })

    if context_res["has_context_overlap"]:
        findings.append({
            "type": "WEAKNESS",
            "severity": "HIGH",
            "title": "Personal Context Overlap",
            "description": context_res["message"]
        })

    # Structured Output Payload
    # NEVER includes plaintext password
    return {
        "score": final_score,
        "classification": classification,
        "color": score_res["color"],
        "summary": score_res["summary"],
        "findings": findings,
        "suggestions": suggestions,
        "metrics": {
            "length": len_res["length"],
            "length_band": len_res["band"],
            "character_type_count": char_res["character_type_count"],
            "unique_character_count": char_res["unique_character_count"],
            "unique_character_ratio": char_res["unique_character_ratio"],
            "pool_size": char_res["estimated_pool_size"],
            "has_lowercase": char_res["has_lowercase"],
            "has_uppercase": char_res["has_uppercase"],
            "has_digits": char_res["has_digits"],
            "has_symbols": char_res["has_symbols"],
            "has_spaces": char_res["has_spaces"],
            "theoretical_entropy_bits": entropy_res["theoretical_bits"],
            "effective_entropy_bits": entropy_res["effective_bits"],
            "entropy_rating": entropy_res["entropy_rating"],
            "crack_resistance_offline": entropy_res["resistance_offline"],
            "crack_resistance_online": entropy_res["resistance_online"]
        },
        "flags": {
            "is_common": common_res["is_common"],
            "has_sequence": seq_res["has_sequence"],
            "has_keyboard_pattern": key_res["has_keyboard_pattern"],
            "has_repetition": rep_res["has_repetition"],
            "has_predictable_structure": struct_res["has_predictable_structure"],
            "has_context_overlap": context_res["has_context_overlap"]
        },
        "score_breakdown": score_res["breakdown"],
        "entropy_details": entropy_res,
        "analyzed_at": datetime.now(timezone.utc).isoformat()
    }
