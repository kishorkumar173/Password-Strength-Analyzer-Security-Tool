# Password Strength Analyzer & Security Suggestion Tool

[![Defensive Cybersecurity](https://img.shields.io/badge/Security-Defensive_In--Memory-10b981?style=for-the-badge&logo=shield)](https://github.com/)
[![Zero-Retention Privacy](https://img.shields.io/badge/Privacy-Zero_Password_Retention-3b82f6?style=for-the-badge&logo=lock)](https://github.com/)
[![NIST SP 800-63B](https://img.shields.io/badge/Compliance-NIST_SP_800--63B-8b5cf6?style=for-the-badge)](https://csrc.nist.gov/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> **An enterprise-grade, defensive cybersecurity tool and Identity & Access Management (IAM) coaching engine designed to analyze password resiliency in real time, detect multi-vector predictability patterns, estimate information entropy, and provide personalized remediation.**

---

## Table of Contents
1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [Cybersecurity & IAM Relevance](#cybersecurity--iam-relevance)
5. [Core Architecture & Workflow](#core-architecture--workflow)
6. [Technology Stack](#technology-stack)
7. [In-Depth Analytical Capabilities](#in-depth-analytical-capabilities)
   - [Length Analysis](#length-analysis)
   - [Character Diversity Analysis](#character-diversity-analysis)
   - [Common Password Detection](#common-password-detection)
   - [Sequence Detection](#sequence-detection)
   - [Keyboard Walk Detection](#keyboard-walk-detection)
   - [Repetition Detection](#repetition-detection)
   - [Predictable Structure & Year Analysis](#predictable-structure--year-analysis)
   - [Personal Context & OSINT Defense](#personal-context--osint-defense)
   - [Information Entropy Estimation](#information-entropy-estimation)
8. [Strength Scoring & Classification](#strength-scoring--classification)
9. [Actionable Suggestion Engine](#actionable-suggestion-engine)
10. [Cryptographic Password Generator & Diceware Passphrases](#cryptographic-password-generator--diceware-passphrases)
11. [Password Policy Evaluator (NIST SP 800-63B)](#password-policy-evaluator-nist-sp-800-63b)
12. [Password Hashing & Salting Sandbox](#password-hashing--salting-sandbox)
13. [Defensive Privacy & Zero-Knowledge Architecture](#defensive-privacy--zero-knowledge-architecture)
14. [Local Installation & Execution](#local-installation--execution)
15. [REST API Documentation](#rest-api-documentation)
16. [Automated Testing & Security Verification](#automated-testing--security-verification)
17. [Safe Demonstration Test Cases](#safe-demonstration-test-cases)
18. [Screenshots & Visual Proof Checklist](#screenshots--visual-proof-checklist)
19. [Security Disclaimer](#security-disclaimer)
20. [Author](#author)

---

## Overview

Traditional password validation systems have long relied on rudimentary composition rules (requiring one uppercase, one lowercase, one digit, and one symbol). However, modern attackers do not brute-force character positions randomly. Instead, adversaries leverage **credential stuffing**, **targeted wordlist mutations (Mask/Rule attacks)**, **OSINT reconnaissance**, and **pattern-based cracking engines** (such as Hashcat and John the Ripper).

Under legacy composition rules, a password like:
```text
Password123!
```
satisfies every requirement (12 characters, uppercase, lowercase, number, symbol), yet it is **one of the fastest passwords to crack** because it adheres directly to human behavioral predictability.

The **Password Strength Analyzer & Security Suggestion Tool** addresses this defensive gap. It evaluates passwords locally and ephemerally, assessing them across **nine distinct structural dimensions**, estimating theoretical vs. effective entropy, calculating a transparent 0–100 composite resilience score, and providing targeted, just-in-time security coaching.

---

## Problem Statement

Weak, predictable, and reused passwords remain the single leading initial access vector in cyberattacks:
1. **Human Habit Over Randomness:** When forced to satisfy arbitrary complexity rules, humans default to formulaic substitutions (capitalizing the first letter, appending `123`, or ending with `!`).
2. **Credential Stuffing & Password Reuse:** When a single non-critical website is breached, automated botnets replay those email/password pairs across banking, enterprise, and social platforms.
3. **Misleading Strength Meters:** Many web forms assign high strength to simple words simply because they are long or contain symbols, misleading users into a false sense of security.
4. **Credential Privacy Risks in Auditing Tools:** Many third-party security meters transmit user passwords across external APIs or retain plaintext in database logs.

---

## Objectives

- **Defensive & Privacy-First:** Never store, log, or transmit plaintext passwords or user-submitted hashes.
- **Multi-Vector Analytical Engine:** Detect dictionary terms, ascending/descending sequences, horizontal keyboard walks, cyclic repetitions, calendar years, and OSINT personal markers.
- **Dual Entropy Calculation:** Compute both theoretical Shannon pool entropy and pattern-adjusted effective entropy, explaining why theoretical formulas alone mislead users.
- **Actionable Remediation:** Provide specific, constructive security suggestions rather than generic "make your password stronger" notices.
- **NIST SP 800-63B Alignment:** Separate organizational policy compliance (PASS/FAIL) from mathematical password strength.
- **Security Awareness & Passphrase Education:** Demystify Diceware passphrases and demonstrate the mechanics of cryptographic salting and key stretching (PBKDF2/Argon2id).

---

## Cybersecurity & IAM Relevance

This project directly maps to enterprise defensive competencies across multiple core cybersecurity domains:

| Role | Industry Impact & Project Demonstration |
| :--- | :--- |
| **Application Security Analyst** | Secure input handling, preventing plaintext logging in application traces, implementing CSRF/CORS protections, secure response headers. |
| **Identity & Access Management (IAM) Specialist** | Implementing authentication controls aligned with NIST SP 800-63B and OWASP ASVS v4.0.3, password blacklisting, designing enterprise registration policies. |
| **SOC / Security Analyst** | Designing telemetry dashboards that monitor organizational password weakness distributions without violating user credential privacy. |
| **Security Awareness Specialist** | Designing real-time just-in-time (JIT) security coaching that educates users against password reuse, OSINT risks, and the necessity of MFA. |
| **Secure Software Developer** | Cryptographic random number generation using CSPRNG (`secrets`), constant-time string comparisons (`hmac.compare_digest`), slow hashing algorithms. |

---

## Core Architecture & Workflow

```
+-------------------------------------------------------------------------+
|                              END USER                                   |
+-------------------------------------------------------------------------+
                                    │
                         Candidate Password + Context
                                    │
                                    ▼
+─────────────────────────────────────────────────────────────────────────+
|               SECURE CLIENT INTERFACE (HTML5 / CSS3 / JS)               |
|  - Real-Time Typing Listener (150ms Debounced)                          |
|  - Show/Hide Password Toggle (Zero console logging)                     |
|  - Instant Client-Side Diversity Matrix                                 |
+─────────────────────────────────────────────────────────────────────────+
                                    │
                          POST /api/analyze (JSON)
                                    │
                                    ▼
+─────────────────────────────────────────────────────────────────────────+
|                FLASK BACKEND ENGINE (Transient Memory)                  |
|  - No Request Body Logging | Security Headers (nosniff, DENY, no-cache) |
+─────────────────────────────────────────────────────────────────────────+
                                    │
                                    ▼
+─────────────────────────────────────────────────────────────────────────+
|                       MODULAR ANALYSIS PIPELINE                         |
|  ┌───────────────────────────┐         ┌──────────────────────────────┐ |
|  │ Length Analysis           │         │ Keyboard Pattern Detector    │ |
|  │ (<8, 8-11, 12-15, 16+)    │         │ (QWERTY Rows, Reverses)      │ |
|  ├───────────────────────────┤         ├──────────────────────────────┤ |
|  │ Character Diversity       │         │ Repetition Detector          │ |
|  │ (Classes, Uniqueness)     │         │ (Runs, Cyclic Substrings)    │ |
|  ├───────────────────────────┤         ├──────────────────────────────┤ |
|  │ Common Password Checker   │         │ Predictable Structure        │ |
|  │ (Dictionary, Leetspeak)   │         │ (TitleCase + Digits + Symbol)│ |
|  ├───────────────────────────┤         ├──────────────────────────────┤ |
|  │ Sequence Detector         │         │ Personal Context Checker     │ |
|  │ (Numeric & Alpha Runs)    │         │ (Name, Year, College OSINT)  │ |
|  └───────────────────────────┘         └──────────────────────────────┘ |
+─────────────────────────────────────────────────────────────────────────+
                                    │
                                    ▼
+─────────────────────────────────────────────────────────────────────────+
|               ENTROPY ESTIMATOR & STRENGTH SCORING ENGINE               |
|  - Theoretical Entropy: L * log2(N)                                     |
|  - Pattern Penalties Deduction -> Effective Entropy                     |
|  - 0-100 Composite Score Calculation                                    |
|  - Tier Mapping: VERY WEAK | WEAK | MODERATE | STRONG | VERY STRONG     |
+─────────────────────────────────────────────────────────────────────────+
                                    │
                                    ▼
+─────────────────────────────────────────────────────────────────────────+
|               SECURITY SUGGESTION & REMEDIATION ENGINE                  |
|  - Specific, Prioritized Remediation Items                              |
|  - Passphrase Recommendation & Universal Defense Guidance (MFA)         |
+─────────────────────────────────────────────────────────────────────────+
                   │                                     │
      Structured Analysis Payload            Safe Metadata (Score, Tier, Flags)
                   │                                     │
                   ▼                                     ▼
+───────────────────────────────────+   +─────────────────────────────────+
|         USER INTERFACE            |   |     SQLITE ANALYTICS DB         |
|  - Animated Color Gauge           |   |  - Table: analyses (No PWD col) |
|  - Findings Badges                |   |  - Table: findings (Categories) |
|  - Actionable Suggestions Cards   |   +─────────────────────────────────+
|  - Transparent Score Breakdown    |                    │
+───────────────────────────────────+                    ▼
                                        +─────────────────────────────────+
                                        |   SOC TELEMETRY DASHBOARD       |
                                        |   - Strength Distribution       |
                                        |   - Common Weakness Frequency   |
                                        |   - Score Ranges Histogram      |
                                        +─────────────────────────────────+
```

---

## Technology Stack

### Backend
- **Python 3.10+ / Flask 3.0+:** Lightweight, clean, highly modular REST API framework.
- **Python `secrets` & `os.urandom`:** Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) backed by hardware entropy.
- **Python `hashlib` & `hmac`:** PBKDF2-HMAC-SHA256 key stretching and `hmac.compare_digest` constant-time verification.
- **SQLite 3:** Embedded relational engine for aggregate telemetry (verified schema with ZERO credential fields).

### Frontend
- **HTML5 & Modern CSS3:** Dark-themed SOC/IAM operational console, responsive CSS Grid/Flexbox, accessible form controls.
- **Vanilla JavaScript (ES6+):** Zero external frontend build dependencies (no npm/Node requirements).
- **Chart.js 4.4+:** Interactive responsive canvas charts for security telemetry and histograms.

---

## In-Depth Analytical Capabilities

### Length Analysis
Evaluates the physical string length into distinct educational bands:
- **< 8 Characters (Very Short):** Critically vulnerable to instantaneous exhaustive enumeration.
- **8–11 Characters (Short):** Satisfies legacy compliance baselines, but inadequate against modern multi-GPU offline clusters.
- **12–15 Characters (Better Length):** Modern recommended baseline for standard consumer authentication.
- **16+ Characters (Strong Length):** Exponentially expands the combinatorial search space against brute-force attacks.

*Important:* The analyzer explains why length alone is insufficient—e.g., `aaaaaaaaaaaaaaaa` has 16 characters but is critically weak due to repetition.

### Character Diversity Analysis
Calculates the presence of 4 standard character classes (lowercase, uppercase, numbers, symbols), unique character counts, and the **unique character ratio** ($\text{Unique} / \text{Length}$). Heavily penalizes inputs that reuse the same 1–2 characters repeatedly.

### Common Password Detection
Matches candidate passwords against `data/common_passwords.txt`, a local, educational blacklist of commonly used passwords. It executes:
1. Exact lowercase matching.
2. **Leetspeak normalization:** Transposes `@` $\to$ `a`, `0` $\to$ `o`, `$` $\to$ `s`, `3` $\to$ `e`, `1`/`!` $\to$ `i`, `7` $\to$ `t`.
3. Substring matching for root words (e.g. `admin`, `welcome`, `password`).

### Sequence Detection
Detects contiguous ascending and descending runs of numbers and letters:
- Numeric: `1234`, `5678`, `9876`, `4321`.
- Alphabetical: `abcd`, `bcde`, `dcba`, `zyxw`.

### Keyboard Walk Detection
Cross-references candidate passwords with QWERTY horizontal row slices, reverse row walks, and common vertical patterns:
- Forward/Backward row walks: `qwerty`, `ytrewq`, `asdfgh`, `lkjhgf`, `zxcvbn`.
- Common walk combinations: `1qaz`, `2wsx`, `3edc`.

### Repetition Detection
Identifies both:
1. **Consecutive character runs:** `aaaaaa`, `111111`.
2. **Periodic cyclic substrings:** `ababab`, `abcabcabc`, `testtest`.

### Predictable Structure & Year Analysis
Flags formulaic habits adopted by users to comply with outdated composition policies:
- **TitleCase + Word + Number + Symbol:** The classic `Password123!` pattern.
- **Word + Calendar Year:** Detects 4-digit years between 1940 and 2035 (e.g., `admin2026`, `welcome2024`).

### Personal Context & OSINT Defense
Allows users to voluntarily input demo contextual fields (First Name, Birth Year, College/Company). The engine verifies whether the password embeds these markers (e.g., `Rahul@123`), explaining how adversaries leverage Open Source Intelligence (OSINT) to build targeted cracking lists.

### Information Entropy Estimation
Calculates theoretical Shannon pool entropy:
$$\text{Entropy}_{\text{theor}} = L \times \log_2(N)$$
Where $L$ is length and $N$ is pool size.

**The Human Non-Randomness Reality:**
Theoretical entropy assumes every character was chosen via independent, uniform machine randomness. The tool calculates an **Effective Entropy** by deducting penalties for human structural crutches.
- `Password123!` has $12 \times \log_2(95) \approx 78.8$ bits of theoretical entropy, but its effective entropy collapses to **under 25 bits** due to predictable structures.

---

## Strength Scoring & Classification

Scores range strictly from **0 to 100**, synthesized from positive contributions and targeted deductions:

```
Score = Clamp(0, 100, Base Contributions - Pattern Penalties)
```

### Positive Contributions (Up to ~100)
- **Length Contribution:** Up to +35
- **Character Diversity:** Up to +15
- **Character Uniqueness Ratio:** Up to +10
- **Structural Complexity Baseline:** Up to +20
- **Dictionary Resistance:** Up to +10
- **High Entropy / Unpredictability Bonus:** Up to +10

### Deductions & Penalties
- **Known Common Password:** -25 to -40
- **Keyboard Walk Sequence:** -12 to -25
- **Sequential Run (Numeric/Alpha):** -10 to -25
- **Repeated Characters / Cycles:** -15 to -30
- **Predictable Formula / Year:** -15 to -20
- **Personal Context Overlap:** -20 to -35

### Five-Tier Classification System

| Score Range | Classification | Color Hex | Security Verdict |
| :---: | :---: | :---: | :--- |
| **0 – 20** | **VERY WEAK** | `#ef4444` (Red) | Extremely vulnerable to dictionary lookups and fast brute-force. |
| **21 – 40** | **WEAK** | `#f97316` (Orange) | Vulnerable to rule-based mask attacks and targeted dictionary mutations. |
| **41 – 60** | **MODERATE** | `#eab308` (Yellow) | Baseline resistance against blind guessing; vulnerable to customized wordlists. |
| **61 – 80** | **STRONG** | `#3b82f6` (Blue) | Strong resistance against automated offline cracking engines. |
| **81 – 100** | **VERY STRONG**| `#10b981` (Green) | High entropy, long, pattern-resistant credential. |

---

## Actionable Suggestion Engine

Unlike generic meters that state *"Make your password stronger"*, PassHound outputs concrete, actionable remediation steps:
- *"Replace numeric runs like '1234' with non-sequential characters."*
- *"Avoid keyboard walks such as 'qwerty'; these are tested in early dictionary attack passes."*
- *"Remove personal markers (first name, birth year) to defend against OSINT-targeted cracking."*
- *"Adopt an open-source password manager (Bitwarden, KeePassXC) to generate 20+ character secrets."*
- *"Enable Multi-Factor Authentication (MFA) via authenticator apps or FIDO2 hardware keys."*

---

## Cryptographic Password Generator & Diceware Passphrases

### CSPRNG Password Generator
- Uses Python's `secrets` module (backed by `CryptGenRandom` / `getrandom`).
- Eliminates deterministic pseudo-random generators (`random` uses the Mersenne Twister, whose internal state can be reconstructed after 624 outputs).
- Configurable length (8 to 48 characters) with guaranteed class distribution.

### Diceware-Style Passphrases
- Inspired by Arnold Reinhold and xkcd #936.
- Chains 3 to 6 randomly selected memorable words separated by hyphens, periods, or spaces.
- Combines long physical length (25+ characters) with high human memorability.

---

## Password Policy Evaluator (NIST SP 800-63B)

Separates **Policy Compliance (PASS/FAIL)** from **Strength Scoring (0–100)**:
- Evaluates minimum length, maximum supported length, dictionary blacklists, and space support.
- Highlights modern NIST SP 800-63B principles:
  - NIST advises **against** forcing composition rules (requiring mixed cases/symbols causes users to write predictable mutations like `Summer2024!`).
  - NIST advises **against** arbitrary periodic 90-day password resets.
  - NIST emphasizes minimum length ($\ge 8$, recommended $12+$) and blacklists against leaked credentials.

---

## Password Hashing & Salting Sandbox

An interactive educational module demonstrating modern password storage:
- **Plaintext vs. One-Way Hash:** Explains why hashing is irreversible verification, not encryption.
- **The Role of Salt:** Demonstrates how 16-byte random salts neutralize precomputed Rainbow Table attacks.
- **Key Stretching & Work Factors:** Side-by-side execution comparing fast unsalted SHA-256 (unsafe for passwords) with slow, iterative PBKDF2-HMAC-SHA256 (600,000 rounds per OWASP guidelines) and Argon2id concepts.
- **Constant-Time Verification:** Uses `hmac.compare_digest` to prevent timing side-channel attacks.

---

## Defensive Privacy & Zero-Knowledge Architecture

The project adheres to strict defensive cybersecurity principles:
1. **Zero Plaintext Storage:** SQLite database schema contains NO columns for passwords.
2. **Zero Plaintext Logging:** Werkzeug HTTP request payload logging is suppressed.
3. **No External Transmission:** Passwords are never sent to third-party cloud services or breach check APIs by default.
4. **Transient In-Memory Analysis:** All string parsing occurs purely in volatile RAM and is discarded immediately after analysis.
5. **Safe Telemetry Only:** Telemetry tables record only anonymous numerical and categorical metadata (score, length, pattern flags, timestamp).

---

## Local Installation & Execution

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.
- Modern web browser (Chrome, Edge, Firefox, Brave).

### Step-by-Step Setup

```bash
# 1. Clone repository
git clone https://github.com/<your-username>/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run automated tests (verify integrity)
python tests/run_all_tests.py

# 6. Launch the server
python run.py
```

Open your browser at **`http://127.0.0.1:5000`** to access the complete application.

---

## REST API Documentation

### 1. Analyze Password
- **Endpoint:** `POST /api/analyze`
- **Request Body:**
```json
{
  "password": "Password123!",
  "first_name": "Rahul",
  "birth_year": "1999",
  "organization": "IIT"
}
```
- **Response (200 OK):**
```json
{
  "status": "success",
  "data": {
    "score": 0,
    "classification": "VERY WEAK",
    "color": "#ef4444",
    "summary": "Password achieved a score of 0/100 and is classified as VERY WEAK...",
    "metrics": {
      "length": 12,
      "character_type_count": 4,
      "unique_character_count": 10,
      "theoretical_entropy_bits": 78.8,
      "effective_entropy_bits": 14.5
    },
    "flags": {
      "is_common": true,
      "has_sequence": true,
      "has_predictable_structure": true
    },
    "suggestions": [...]
  }
}
```

### 2. Generate CSPRNG Password
- **Endpoint:** `POST /api/generate-password`
- **Request:** `{"length": 20, "uppercase": true, "lowercase": true, "digits": true, "symbols": true}`
- **Response (200 OK):** `{"status": "success", "data": {"password": "...", "length": 20}}`

### 3. Generate Diceware Passphrase
- **Endpoint:** `POST /api/generate-passphrase`
- **Request:** `{"word_count": 4, "separator": "-"}`
- **Response (200 OK):** `{"status": "success", "data": {"passphrase": "glacier-compass-safari-summit"}}`

### 4. Evaluate Policy Compliance
- **Endpoint:** `POST /api/check-policy`
- **Request:** `{"password": "...", "policy": {"min_length": 12, "reject_common": true}}`
- **Response (200 OK):** `{"status": "success", "data": {"status": "PASS", "passed": true}}`

### 5. Aggregate Dashboard Telemetry
- **Endpoint:** `GET /api/dashboard/stats`
- **Response (200 OK):** Returns anonymous counts, averages, and distribution histograms.

---

## Automated Testing & Security Verification

The test suite covers **30 explicit test scenarios** and full pytest test cases:

```bash
# Execute standalone 30-scenario runner
python tests/run_all_tests.py

# Execute pytest suite with coverage
pytest tests/
```

### Automated Test Coverage Matrix

| Test ID | Scenario | Input | Expected Result | Actual Result | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| 1 | Empty password | `''` | Score 0, VERY WEAK | Score 0, VERY WEAK | **PASS** |
| 2 | One-character password | `'x'` | Score <= 20, VERY WEAK | Score 15, VERY WEAK | **PASS** |
| 3 | Short numeric password | `'4921'` | Length < 8, VERY WEAK | Score 25, WEAK | **PASS** |
| 4 | Common password | `'password123'` | Flagged is_common, WEAK | is_common=True, VERY WEAK | **PASS** |
| 5 | Long repeated password | `'aaaaaaaaaaaaaaaa'` | High repetition, Score <= 30 | Score 15, rep=True | **PASS** |
| 6 | Lowercase only | `'unpredictable...'` | Types = 1 | Types = 1 | **PASS** |
| 7 | Uppercase only | `'UNPREDICTABLE...'` | has_upper=True, has_lower=False | has_upper=True, has_lower=False | **PASS** |
| 8 | Numbers only | `'849204719385'` | has_digits=True, types=1 | types=1 | **PASS** |
| 9 | Symbols only | `'!@#$%^&*()-_'` | has_symbols=True | has_symbols=True | **PASS** |
| 10 | Mixed characters | `'K8#mZ$9vW@2x'` | types=4, Score >= 60 | types=4, Score 80 | **PASS** |
| 11 | Sequential numbers | `'mySecret12345'` | has_sequence=True | has_sequence=True | **PASS** |
| 12 | Reverse numeric sequence | `'mySecret54321'` | has_sequence=True | has_sequence=True | **PASS** |
| 13 | Sequential letters | `'keycdefghsecret'` | has_sequence=True | has_sequence=True | **PASS** |
| 14 | Keyboard sequence | `'myqwertyAccess'` | has_keyboard_pattern=True | has_keyboard=True | **PASS** |
| 15 | Repeated characters | `'admin77777pass'` | has_repetition=True | has_rep=True | **PASS** |
| 16 | Repeated substring | `'abcabcabc12!'` | has_repetition=True | has_rep=True | **PASS** |
| 17 | Common word + number | `'welcome123'` | Score <= 30, Common | Score 0, is_common=True | **PASS** |
| 18 | Word + year | `'Summer2024!'` | has_predictable_structure=True | struct=True | **PASS** |
| 19 | Personal name overlap | `'Rahul@2024'` | has_context_overlap=True | context=True | **PASS** |
| 20 | Birth year overlap | `'Secret1999!'` | has_context_overlap=True | context=True | **PASS** |
| 21 | Long passphrase input | `'correct-horse...'`| Score >= 65, STRONG | Score 75, STRONG | **PASS** |
| 22 | Unicode handling | `'Pässwörd!123_🔒'` | Processed without crash | Length 14 | **PASS** |
| 23 | Space handling | `'galaxy river...'` | has_spaces=True | has_spaces=True | **PASS** |
| 24 | Maximum length defense | `'A' * 500` | Bounded to <= 256 | Length 256 | **PASS** |
| 25 | Score boundaries | `0-100 range` | Score within [0, 100] | Min=0, Max=100 | **PASS** |
| 26 | Suggestion generation | `'123456'` | Suggestions count > 0 | Count 7 | **PASS** |
| 27 | CSPRNG generation | `gen length=20` | Length 20, CSPRNG | Length 20, Python secrets | **PASS** |
| 28 | Password not in DB | `SensitivePwdTest` | Absent from database row | Absent | **PASS** |
| 29 | Zero logging in error | `None` | Graceful handling | Handled | **PASS** |
| 30 | Safe Analytics Storage | `SQLite Metadata` | Metadata records > 0 | Verified | **PASS** |

---

## Safe Demonstration Test Cases

All demonstration testing uses **strictly synthetic demo inputs**:

1. **`123456`** $\to$ `VERY WEAK (Score 0/100)`: Common password + critically short + numeric sequence.
2. **`Password123!`** $\to$ `VERY WEAK (Score 0/100)`: Satisfies traditional complexity but matches root dictionary word + numeric sequence + classic titlecase template.
3. **`aaaaaaaaaaaaaaaa`** $\to$ `VERY WEAK (Score 15/100)`: Long (16 chars) but zero unpredictability (single character repetition).
4. **`qwerty2026!`** $\to$ `VERY WEAK (Score 0/100)`: QWERTY keyboard walk + future calendar year mutation.
5. **`correct-horse-battery-staple`** $\to$ `STRONG (Score 75/100)`: Diceware passphrase with high character length and pattern resistance.
6. **`J9#mK$2vL@8zP&4w`** $\to$ `VERY STRONG (Score 95/100)`: Cryptographically generated 16-character string with high character diversity and no sequential crutches.

---

## Screenshots & Visual Proof Checklist

Refer to [`screenshots/README.md`](screenshots/README.md) for full visual capture guidance:
- `01_project_structure.png`: Project folder tree and modular files.
- `02_architecture_diagram.png`: End-to-end data flow and privacy barrier.
- `03_analyzer_homepage.png`: Dark-themed SOC/IAM security dashboard.
- `04_hidden_password_field.png`: Obfuscated password field with toggle.
- `05_very_weak_result.png`: Evaluation of synthetic input `123456`.
- `06_weak_result.png`: Evaluation of synthetic input `Password123!`.
- `07_moderate_result.png`: Evaluation of standard 12-char mixed password.
- `08_strong_result.png`: Evaluation of Diceware passphrase.
- `09_very_strong_result.png`: Evaluation of 20-character CSPRNG secret.
- `10_sequence_detection.png`: Numeric and alphabetic sequence findings.
- `11_keyboard_pattern.png`: QWERTY walk warning badge.
- `12_repetition_detection.png`: Cyclic substring repetition alert.
- `13_policy_checker_pass.png`: NIST SP 800-63B policy evaluation verdict.
- `14_hashing_lab_comparison.png`: SHA-256 vs PBKDF2 salt & key stretching.
- `15_analytics_dashboard_charts.png`: Chart.js distribution graphs.
- `16_automated_tests_pass.png`: Terminal output showing all 30 tests passed.
- `17_database_schema_verification.png`: SQLite schema proving zero password columns.

---

## Security Disclaimer

> **DEFENSIVE CYBERSECURITY DISCLAIMER:**  
> This software is created strictly for defensive cybersecurity education, Identity & Access Management (IAM) coaching, and academic demonstration.  
> - It does NOT store or log user passwords.  
> - It does NOT include password-cracking or credential-stealing utilities.  
> - It does NOT attempt brute-force attacks against third-party authentication services.  
> - All demonstration test credentials in this documentation are fictional, synthetic examples. Never reuse demonstration passwords for real-world accounts.

---

## Author

**Cybersecurity Engineering Student**  
Course Project: *Password Strength Analyzer & Security Suggestion Tool*  
Focus: Defensive Application Security, Identity & Access Management (IAM), Secure Coding.
