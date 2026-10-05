# NIST SP 800-63B Alignment & Modern IAM Guidance

## Background: NIST Digital Identity Guidelines

Special Publication 800-63B published by the National Institute of Standards and Technology (NIST) represents the authoritative baseline for modern government and enterprise authentication. It fundamentally overhauled legacy password management standards.

## Legacy Misconceptions vs. NIST SP 800-63B Standards

| Domain | Legacy Practice (Discouraged) | NIST SP 800-63B Guidance | PassHound Implementation |
| :--- | :--- | :--- | :--- |
| **Composition Rules** | Mandatory uppercase, lowercase, numbers, and symbols. | **Discontinued.** Composition rules create user frustration and lead directly to predictable mutations (`Password123!`). | Analyzes character types but does NOT mandate them for high strength. |
| **Minimum Length** | 8 characters or fewer. | Minimum 8 characters; recommends **12 to 16+ characters** for human accounts. | Assigns 35/100 points to length; bands inputs into educational tiers. |
| **Maximum Length** | Arbitrary caps (e.g. 16 or 24 characters). | Systems **MUST support at least 64 characters** to accommodate long passphrases. | Supports inputs up to 256 characters. |
| **Dictionary Blacklists** | Basic exact-match lists or none at all. | **Mandatory screening** against lists of known breached, dictionary, and predictable passwords. | Features local blacklist matching with leetspeak normalization. |
| **Whitespace / Spaces** | Rejecting spaces in input fields. | Systems **MUST permit ASCII and Unicode spaces** to facilitate multi-word passphrases. | Spaces fully permitted and highlighted as valid passphrase separators. |
| **Periodic Password Resets** | Forcing users to change passwords every 90 days. | **Discontinued.** Arbitrary resets cause users to select predictable incrementing substitutions (`Summer2023!` $\to$ `Summer2024!`). | Educational awareness rules advise rotating credentials only upon confirmed/suspected breach. |
| **Multi-Factor Auth (MFA)** | Considered an optional add-on. | Recommended / mandatory for elevated assurance levels (AAL2 and AAL3). | Prioritizes MFA recommendations in the suggestion engine. |
