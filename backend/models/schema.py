"""
Schema and Data Architecture Specification.

PRIVACY ARCHITECTURE MANIFESTO:
1. No Plaintext Passwords:
   The database schema strictly contains zero columns for passwords, passphrases,
   or user secrets.
2. No Reversible Hashes for Arbitrary Inputs:
   Storing user-submitted test passwords as hashes would construct a breach-vulnerable
   credential target. Therefore, this tool strictly acts as a stateless,
   zero-knowledge analysis engine.
3. Aggregate Metadata Only:
   Only mathematical scores, classification tiers, string length, and boolean pattern flags
   are recorded for SOC defensive analytics.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SafeAnalysisRecord:
    """Represents a persisted metadata row in the analyses table."""
    analysis_id: int
    score: int
    classification: str
    password_length: int
    unique_character_ratio: float
    weakness_count: int
    theoretical_entropy: float
    effective_entropy: float
    has_sequence: bool
    has_repetition: bool
    has_keyboard_pattern: bool
    is_common: bool
    created_at: str


@dataclass
class SafeFindingRecord:
    """Represents a persisted metadata finding row."""
    finding_id: int
    analysis_id: int
    finding_type: str  # POSITIVE or WEAKNESS
    severity: str      # CRITICAL, HIGH, MEDIUM, INFO, SUCCESS
    title: str
    description: str
