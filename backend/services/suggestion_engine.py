"""
Security Suggestion Engine.
Transforms analytical findings into prioritized, constructive, actionable recommendations.
Adheres to strict defensive and educational principles:
  - Never echoes user passwords in suggestions
  - Avoids vague advice like 'make it better'
  - Provides concrete security reasons and defense-in-depth guidance (MFA, password managers)
"""

from typing import Dict, Any, List


def generate_suggestions(
    length_result: Dict[str, Any],
    char_result: Dict[str, Any],
    common_result: Dict[str, Any],
    sequence_result: Dict[str, Any],
    keyboard_result: Dict[str, Any],
    repetition_result: Dict[str, Any],
    structure_result: Dict[str, Any],
    context_result: Dict[str, Any],
    score: int
) -> List[Dict[str, Any]]:
    """
    Synthesizes specific, prioritized security recommendations based on analysis findings.

    Returns:
      List of suggestion items with priority, title, description, and action.
    """
    suggestions: List[Dict[str, Any]] = []

    # Priority 1: Common Password (Critical emergency)
    if common_result.get("is_common"):
        suggestions.append({
            "priority": "CRITICAL",
            "category": "Known Common Password",
            "title": "Replace Immediately with a Unique Secret",
            "description": (
                "Your password matches or closely mimics a known entry in common password dictionaries. "
                "Attackers use automated lists to guess these in milliseconds."
            ),
            "action": "Do not use this password for any account. Generate a random password or use a multi-word passphrase."
        })

    # Priority 2: Length Deficiency
    length = length_result.get("length", 0)
    if length < 8:
        suggestions.append({
            "priority": "CRITICAL",
            "category": "Insufficient Length",
            "title": "Increase Length to at least 12-16 Characters",
            "description": (
                f"Your password is only {length} characters long. Modern computing hardware can exhaustively "
                "search short password spaces rapidly."
            ),
            "action": "Extend the password to 14-16+ characters or adopt a 4-word random passphrase."
        })
    elif 8 <= length < 12:
        suggestions.append({
            "priority": "HIGH",
            "category": "Borderline Length",
            "title": "Consider Lengthening Beyond Legacy Minimums",
            "description": (
                "While 8-11 characters meets older requirements, modern standards (e.g., NIST SP 800-63B) "
                "recommend at least 12 characters to provide a defensive safety margin against offline attacks."
            ),
            "action": "Add 4 or more unpredictable characters or words to your credential."
        })

    # Priority 3: Personal Context Overlap
    if context_result.get("has_context_overlap"):
        suggestions.append({
            "priority": "HIGH",
            "category": "Personal Information Overlap",
            "title": "Remove Personal Details (Name, Year, College)",
            "description": (
                "Your password contains personal contextual identifiers. Cybercriminals routinely harvest "
                "public social media profiles (OSINT) to build custom wordlists targeting personal info."
            ),
            "action": "Remove your name, birth year, and organization references from all passwords."
        })

    # Priority 4: Predictable Sequences
    if sequence_result.get("has_sequence"):
        seq_names = ", ".join([s["type"] for s in sequence_result.get("sequences_found", [])[:2]])
        suggestions.append({
            "priority": "HIGH",
            "category": "Sequential Patterns",
            "title": "Eliminate Predictable Ascending/Descending Sequences",
            "description": (
                f"Detected sequential patterns ({seq_names}). Sequence guessing is hard-coded into "
                "every standard password cracking tool."
            ),
            "action": "Replace numeric runs like '1234' or alphabetic runs like 'abcd' with non-sequential characters."
        })

    # Priority 5: Keyboard Walks
    if keyboard_result.get("has_keyboard_pattern"):
        suggestions.append({
            "priority": "HIGH",
            "category": "Keyboard Walks",
            "title": "Avoid Keyboard Row and Column Walks",
            "description": (
                "Keyboard patterns like 'qwerty', 'asdf', or diagonal paths feel complex to type "
                "but are among the very first patterns tested by dictionary attack engines."
            ),
            "action": "Avoid tracing contiguous keys on your physical keyboard."
        })

    # Priority 6: Character and Substring Repetitions
    if repetition_result.get("has_repetition"):
        suggestions.append({
            "priority": "MEDIUM",
            "category": "Pattern Repetition",
            "title": "Eliminate Repetitive Characters and Cycles",
            "description": (
                "Repeated characters (e.g., 'aaaa') or repeated syllables (e.g., 'abab') create the "
                "illusion of length while failing to add mathematical unpredictability."
            ),
            "action": "Ensure each character or word contributes novel, unrepeated entropy."
        })

    # Priority 7: Predictable Human Composition Structure
    if structure_result.get("has_predictable_structure"):
        suggestions.append({
            "priority": "MEDIUM",
            "category": "Formulaic Structure",
            "title": "Avoid Formulaic 'Capital + Word + Number + Symbol' Templates",
            "description": (
                "Structuring passwords as 'Word123!' or appending calendar years directly reflects "
                "habitual human compliance with older composition rules. Mask attacks easily break this structure."
            ),
            "action": "Distribute variety unpredictably throughout the string or switch to a multi-word passphrase."
        })

    # Priority 8: Low Character Diversity
    if char_result.get("character_type_count", 0) < 3 and length >= 8:
        suggestions.append({
            "priority": "MEDIUM",
            "category": "Character Set Diversity",
            "title": "Broaden the Character Selection Pool",
            "description": (
                "Your password is drawn from a limited character pool. Expanding to mixed case, digits, "
                "and symbols increases the combinatorial space."
            ),
            "action": "Combine uppercase, lowercase, numbers, and special symbols where permitted."
        })

    # Universal Defensive Guidance (Standard for high-security baseline)
    suggestions.append({
        "priority": "INFO",
        "category": "Credential Hygiene",
        "title": "Never Reuse Passwords Across Accounts",
        "description": (
            "Password reuse is the primary enabler of Credential Stuffing breaches. If a single service "
            "leaks your password, attackers test the same credentials across banking, email, and social services."
        ),
        "action": "Ensure every single account possesses an entirely unique secret."
    })

    suggestions.append({
        "priority": "INFO",
        "category": "Password Managers",
        "title": "Use an Open-Source or Audited Password Manager",
        "description": (
            "Password managers eliminate the cognitive burden of remembering complex secrets and "
            "enable effortless generation of 20+ character random strings."
        ),
        "action": "Consider tools like Bitwarden, 1Password, or KeePassXC."
    })

    suggestions.append({
        "priority": "INFO",
        "category": "Defense-in-Depth",
        "title": "Always Enable Multi-Factor Authentication (MFA)",
        "description": (
            "Even an mathematically unbreakable password cannot protect you from phishing or session theft. "
            "MFA (authenticator apps or FIDO2/WebAuthn hardware keys) provides an indispensable second layer of defense."
        ),
        "action": "Activate app-based or hardware-key MFA on all supported accounts."
    })

    return suggestions
