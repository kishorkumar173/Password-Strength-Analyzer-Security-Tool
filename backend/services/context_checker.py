"""
Personal Information Context Checker.
Allows users to voluntarily test whether their password contains easily guessed
personal markers (e.g., name, birth year, organization/college).
STRICT PRIVACY: All context comparisons are ephemeral, strictly in-memory,
and NEVER stored or logged.
"""

from typing import Dict, Any, List, Optional


def check_personal_context(
    password: str,
    first_name: Optional[str] = None,
    birth_year: Optional[str] = None,
    organization: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates whether the password overlaps with user-provided contextual identifiers.

    Attack Context:
      Targeted spear phishing and OSINT-driven dictionary attacks generate customized
      wordlists using the victim's name, employer, university, and family dates.

    Returns:
      Dict with has_context_overlap, matched_items, penalty, and message.
    """
    if not password:
        return {
            "has_context_overlap": False,
            "matched_items": [],
            "penalty": 0,
            "message": "No password provided."
        }

    matched_items: List[str] = []
    penalty = 0
    lower_pwd = password.lower()

    # 1. First Name Check (min length 3)
    if first_name and len(first_name.strip()) >= 3:
        clean_name = first_name.strip().lower()
        if clean_name in lower_pwd:
            matched_items.append("First Name")
            penalty += 25

    # 2. Birth Year Check (min length 4)
    if birth_year and len(birth_year.strip()) == 4:
        clean_year = birth_year.strip()
        if clean_year in password:
            matched_items.append("Birth Year")
            penalty += 20

    # 3. Organization / College Check (min length 3)
    if organization and len(organization.strip()) >= 3:
        clean_org = organization.strip().lower()
        if clean_org in lower_pwd:
            matched_items.append("Organization / College Name")
            penalty += 20

    penalty = min(35, penalty)
    has_overlap = len(matched_items) > 0

    if has_overlap:
        items_str = ", ".join(matched_items)
        message = (
            f"Password appears to contain personal contextual information ({items_str}). "
            "Attackers routinely scrape social media profiles (OSINT) to crack passwords containing personal details."
        )
    else:
        message = "No personal context overlap detected."

    return {
        "has_context_overlap": has_overlap,
        "matched_items": matched_items,
        "penalty": penalty,
        "message": message
    }
