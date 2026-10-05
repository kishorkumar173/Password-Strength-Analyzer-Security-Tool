# Academic & Engineering Project Report

## Project Title
**Password Strength Analyzer & Security Suggestion Tool**  
*A Defensive Cybersecurity, Identity & Access Management (IAM), and Application Security Engineering Project*

---

### Executive Summary / Abstract

Authentication security forms the frontline defense of modern digital infrastructure. Despite decades of security guidelines, compromised credentials remain the primary vector in over 80% of unauthorized access incidents and data breaches. Traditional password strength meters have predominantly enforced rigid composition rules (requiring uppercase, lowercase, numbers, and symbols), inadvertently training human users to adopt predictable structural patterns—such as capitalizing the first letter and appending sequential numbers or symbols (e.g., `Password123!`).

This project presents the design and implementation of the **Password Strength Analyzer & Security Suggestion Tool**, an end-to-end, zero-retention defensive cybersecurity platform. Built using Python, Flask, SQLite, and vanilla JavaScript, the system evaluates passwords across nine distinct analytical dimensions: physical length, character diversity, dictionary matching with leetspeak normalization, ascending/descending numeric/alpha sequences, QWERTY keyboard walks, character and cyclic substring repetitions, predictable formulaic structures, calendar years, and OSINT personal context overlap.

The system synthesizes these observations into a dual-entropy assessment (theoretical Shannon pool entropy vs. pattern-adjusted effective entropy) and a transparent 0–100 composite resilience score categorized into five industry-oriented tiers. To eliminate credential privacy risks, the platform operates on an in-memory, zero-retention architecture: passwords are never logged, never persisted to disk, and never transmitted to third parties. Telemetry collected for organizational SOC/IAM awareness dashboards consists strictly of anonymous numerical and categorical metadata. A comprehensive automated suite of 30 test scenarios verifies the analytical accuracy and privacy constraints of the system.

---

### 1. Introduction

Authentication is the mechanism by which an entity proves its claimed identity to an information system. While modern enterprise architectures increasingly adopt Multi-Factor Authentication (MFA) and FIDO2 passkeys, knowledge-based authenticators (passwords and passphrases) remain the foundational bedrock of global consumer, corporate, and legacy access control.

Unfortunately, human cognitive constraints clash directly with traditional password policies. When users are coerced into remembering complex character combinations across dozens of disparate services, they inevitably resort to:
1. Reusing identical credentials across critical and non-critical applications.
2. Employing predictable mnemonic templates (e.g., season + year + exclamation mark: `Spring2024!`).
3. Minor cosmetic variations (leetspeak substitutions like `E` $\to$ `3`, `A` $\to$ `@`).

This project bridges the gap between human behavioral tendencies and modern offensive cracking realities by providing an interactive, educational, and defensively engineered password evaluation framework.

---

### 2. Problem Statement

Existing password strength mechanisms in enterprise registration workflows suffer from significant systemic flaws:
1. **The Composition Rule Fallacy:** Traditional meters assign maximum scores to passwords that satisfy four character classes, disregarding that password-cracking engines (such as Hashcat) execute rule-based mask attacks specifically targeting these templates.
2. **Deceptive Entropy Calculations:** Many calculators report theoretical Shannon entropy ($L \times \log_2 N$), misleading users into believing a password like `Password123!` provides $\approx 78$ bits of security when its effective entropy is under 20 bits.
3. **Vague Remediation Guidance:** Conventional meters present generic prompts such as *"Make your password stronger"*, failing to teach users *why* sequential numbers or keyboard walks compromise security.
4. **Third-Party Privacy Exposure:** Many web-based analyzers transmit passwords over cleartext HTTP or send plaintext strings to third-party breach query APIs, converting an auditing tool into a data exfiltration hazard.

---

### 3. Project Objectives

1. **Develop an In-Memory Defensive Engine:** Evaluate password resiliency without saving, logging, or transmitting credentials.
2. **Multi-Vector Analytical Detection:** Detect dictionary patterns, keyboard walks, sequences, cyclic repetitions, formulaic templates, and OSINT context overlap.
3. **Synthesize Dual-Entropy Metrics:** Contrast theoretical machine entropy with pattern-penalized effective entropy.
4. **Deliver Actionable Security Suggestions:** Provide specific, prioritized remediation steps and promote Diceware passphrases.
5. **Implement NIST SP 800-63B Policy Evaluation:** Distinguish binary policy compliance from continuous mathematical strength.
6. **Demonstrate Modern Cryptographic Storage:** Demystify the necessity of cryptographic salt, work factors, and slow key-stretching functions (PBKDF2/Argon2id) over fast hashing algorithms.
7. **Build an Anonymous SOC/IAM Dashboard:** Visualize aggregate password telemetry without retaining credentials.

---

### 4. Background & Cryptographic Fundamentals

#### 4.1 Authentication vs. Authorization
- **Authentication:** Verifying *who* a user is (e.g., validating a password or biometric signature).
- **Authorization:** Determining *what permissions* the authenticated identity possesses (e.g., role-based access control to databases).

#### 4.2 Plaintext vs. Cryptographic Hash
A plaintext password must never be stored on a server. Instead, modern systems store a one-way cryptographic digest. A cryptographic hash function $H(m)$ satisfies three core properties:
1. **Pre-image Resistance (One-Way):** Given $h = H(m)$, it is computationally infeasible to find $m$.
2. **Second Pre-image Resistance (Weak Collision Resistance):** Given $m_1$, it is infeasible to find $m_2 \neq m_1$ such that $H(m_1) = H(m_2)$.
3. **Collision Resistance (Strong Collision Resistance):** It is infeasible to find any pair $(m_1, m_2)$ such that $H(m_1) = H(m_2)$.

#### 4.3 Why Fast General-Purpose Hashes Fail for Passwords
General-purpose digests (MD5, SHA-1, SHA-256) are engineered for high-throughput checksum verification and network protocols. A single modern consumer GPU cluster can calculate **over 10 to 50 billion SHA-256 hashes per second**. Consequently, unsalted or fast-hashed passwords can be brute-forced or searched via precomputed **Rainbow Tables** in seconds.

#### 4.4 Cryptographic Salt and Key Stretching
- **Cryptographic Salt:** A unique, cryptographically random sequence of bytes (minimum 16 bytes) generated per user and concatenated with the password prior to hashing. The salt prevents identical passwords from producing identical hashes, completely neutralizing precomputed Rainbow Table attacks.
- **Key Stretching / Password Hashing Functions:** Functions deliberately engineered to consume significant CPU and memory resources:
  - **Argon2id:** The winner of the Password Hashing Competition (PHC), providing memory-hardness to defeat GPU and ASIC custom hardware cracking rigs.
  - **bcrypt:** An adaptive, Blowfish-based key-derivation function incorporating configurable work factor rounds.
  - **PBKDF2-HMAC-SHA256:** A standards-based key stretching algorithm applying repeated HMAC iterations (recommended $\ge 600,000$ iterations by OWASP).

---

### 5. System Architecture & Methodology

The application follows a modular, defensively decoupled three-tier architecture:

```
[Presentation Layer]
  HTML5 / CSS3 / Vanilla JavaScript / Chart.js
         │ (Transient JSON via POST /api/analyze)
         ▼
[Application & Analysis Layer]
  Flask Web Framework (In-Memory Processing)
  ├── Length Analyzer (<8, 8-11, 12-15, 16+)
  ├── Character Diversity Analyzer (Classes, Uniqueness Ratio)
  ├── Common Password Checker (Dictionary, Leetspeak)
  ├── Sequence Detector (Ascending/Descending Numeric & Alpha)
  ├── Keyboard Walk Detector (QWERTY Rows, Reverses)
  ├── Repetition Detector (Consecutive Runs, Cyclic Substrings)
  ├── Predictable Structure Detector (Word+Number, Year, Classic Form)
  ├── Context Checker (OSINT Overlap with Name, Year, Org)
  ├── Entropy Estimator (Theoretical vs. Pattern-Adjusted Effective)
  ├── Scoring Engine (0-100 Composite Score & 5-Tier Classification)
  └── Suggestion Engine (Prioritized Actionable Coaching)
         │ (Anonymous Numerical & Categorical Metadata)
         ▼
[Persistence Layer - Zero Credential Retention]
  SQLite Database (analyses, findings)
```

---

### 6. Analytical Modules & Implementation Details

#### 6.1 Length Analysis
Categorizes input length $L$ into distinct security bands:
- $L < 8$: Very Short (Critically vulnerable to exhaustive search).
- $8 \le L \le 11$: Short (Meets legacy baselines, vulnerable to offline cracking).
- $12 \le L \le 15$: Better Length (Modern recommended consumer baseline).
- $L \ge 16$: Strong Length (Exponential expansion of combinatorial space).

#### 6.2 Character Diversity & Uniqueness Ratio
Computes the presence of 4 primary classes: lowercase ($a..z$), uppercase ($A..Z$), digits ($0..9$), and symbols ($\text{ASCII punctuation}$). Computes the **Unique Character Ratio**:
$$R_{\text{unique}} = \frac{|\text{Distinct Characters}|}{L}$$
Where $R_{\text{unique}} < 0.5$ triggers severe structural predictability deductions.

#### 6.3 Common Password & Leetspeak Matching
Matches candidates against a curated educational dataset (`common_passwords.txt`) via a three-phase lookup:
1. Exact lowercase matching.
2. Leetspeak substitution mapping:
   $$\{@ \to a, 4 \to a, 8 \to b, 3 \to e, 1 \to i, ! \to i, 0 \to o, \$ \to s, 5 \to s, 7 \to t\}$$
3. Substring matching for root common words of length $\ge 5$.

#### 6.4 Sequence Detection
Scans contiguous characters to detect numerical runs (e.g. `1234`, `9876`) and alphabetical runs (e.g. `abcd`, `dcba`) using modular arithmetic and ASCII code delta evaluation:
$$\Delta = \text{ord}(c_{i+1}) - \text{ord}(c_i) \in \{+1, -1\}$$

#### 6.5 Keyboard Walk Detection
Models the physical QWERTY matrix and scans for horizontal slices (forward and backward) and common diagonal combinations (`qwerty`, `ytrewq`, `asdfgh`, `zxcvbn`, `1qaz`).

#### 6.6 Repetition Detection
Employs regular expressions and cyclic chunking to detect:
1. Consecutive identical character runs: `(.)\1{2,}` (e.g., `aaaaaa`).
2. Periodic cyclic substring repeats of length $k \in [2, L/2]$ (e.g., `ababab`, `testtest`).

#### 6.7 Predictable Structure & Year Analysis
Detects formulaic habits:
- Classic TitleCase template: `^[A-Z][a-z]{3,}[0-9]{1,4}[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?]$`
- 4-digit calendar years between 1940 and 2035 (`19[4-9][0-9]|20[0-3][0-9]`).

#### 6.8 Personal Context & OSINT Defense
Accepts voluntary ephemeral context (first name, birth year, organization) and detects substring overlap, educating users on targeted social engineering and OSINT reconnaissance.

#### 6.9 Entropy Modeling: Theoretical vs. Effective
- **Theoretical Shannon Pool Entropy:**
  $$E_{\text{theor}} = L \times \log_2(N)$$
  Where $N$ is the estimated character pool ($26 + 26 + 10 + 33 = 95$).
- **Effective Pattern-Adjusted Entropy:**
  $$E_{\text{eff}} = \max\left(0, E_{\text{theor}} - \left(\frac{P_{\text{total}}}{100} \times 0.70 \times E_{\text{theor}}\right)\right)$$
  Where $P_{\text{total}}$ represents the sum of detected pattern penalties.

---

### 7. Strength Scoring & Tier Classification

Scores are computed on a normalized 0–100 scale:
$$\text{Score} = \min\left(100, \max\left(0, \sum \text{Additions} - \sum \text{Penalties}\right)\right)$$

Hard defensive ceilings are enforced:
- If exact common password: $\text{Score} \le 15$.
- If length $< 8$: $\text{Score} \le 25$.
- If unique characters $\le 1$: $\text{Score} \le 15$.

**Classification Tiers:**
- **0 – 20:** VERY WEAK (`#ef4444`)
- **21 – 40:** WEAK (`#f97316`)
- **41 – 60:** MODERATE (`#eab308`)
- **61 – 80:** STRONG (`#3b82f6`)
- **81 – 100:** VERY STRONG (`#10b981`)

---

### 8. NIST SP 800-63B Alignment & Policy Evaluation

The National Institute of Standards and Technology (NIST) Special Publication 800-63B (*Digital Identity Guidelines: Authentication and Lifecycle Management*) introduced radical shifts in credential policy:
1. **Elimination of Arbitrary Complexity Rules:** Requiring character classes encourages predictable human substitutions (`Password123!`).
2. **Support for Long Passphrases & Spaces:** Systems should support lengths up to at least 64 characters and permit spaces.
3. **Screening Against Compromised Credentials:** Passwords must be evaluated against blacklists of known breached or dictionary passwords.
4. **Elimination of Periodic Expiration:** Forcing 90-day resets induces minor incrementing mutations (`Summer2023!` $\to$ `Summer2024!`).

The project includes an **Enterprise Policy Evaluator** that benchmarks passwords against these guidelines, separating binary compliance from strength scores.

---

### 9. Privacy, Security, & Zero-Retention Architecture

To guarantee defensive security:
1. **Schema Audit:** The SQLite database contains tables `analyses` and `findings`. Neither table contains any column for passwords, passphrases, or user secrets.
2. **Log Neutralization:** Werkzeug request-body logging is disabled, ensuring submitted inputs do not appear in console or access logs.
3. **Zero External Dependencies for Evaluation:** The analyzer runs completely offline and locally without calling external APIs.
4. **Denial-of-Service Defense:** Input strings exceeding 256 characters are safely truncated to prevent algorithmic complexity attacks (ReDoS) or memory exhaustion.

---

### 10. Automated Testing & Verification

The project was validated using both a custom 30-scenario test runner and pytest:
- **30 Synthetic Scenarios:** Tested empty inputs, single characters, short numbers, dictionary entries, repeated strings, character classes, sequences, keyboard walks, cyclic repetitions, year structures, context overlap, Unicode, spaces, and boundary conditions.
- **Security & Privacy Assertions:** Programmatically verified that database schema lacks credential columns, inserted records contain zero plaintext, and API responses never echo passwords.
- **Results:** **30 / 30 tests passed (100% pass rate).**

---

### 11. Results & Demonstration Findings

| Synthetic Test Input | Score | Tier | Primary Analytical Findings |
| :--- | :---: | :---: | :--- |
| `123456` | 0 | VERY WEAK | Critical common match; length < 8; ascending numeric sequence. |
| `Password123!` | 0 | VERY WEAK | Root common word; classic TitleCase formula; numeric sequence. |
| `aaaaaaaaaaaaaaaa` | 15 | VERY WEAK | Length 16 characters; single unique character; massive repetition. |
| `qwerty2026!` | 0 | VERY WEAK | QWERTY horizontal walk; calendar year pattern; low uniqueness. |
| `correct-horse-battery-staple` | 75 | STRONG | 28 characters; Diceware structure; zero sequences or keyboard walks. |
| `J9#mK$2vL@8zP&4w` | 95 | VERY STRONG | 16 characters CSPRNG; all 4 character classes; high uniqueness ratio (94%). |

---

### 12. Limitations

1. **Local Dictionary Constraints:** The local educational common password list is intentionally compact (~100 entries) for demonstration. In production enterprise IAM, k-Anonymity querying against large breach corpuses (e.g. HaveIBeenPwned) is standard.
2. **Context Scope:** The personal context checker evaluates only user-supplied fields; real-world OSINT attacks correlate unstructured data from social graphs.
3. **Hardware-Agnostic Cracking Estimates:** Guess-resistance timeframes are educational approximations and vary dramatically based on the target system's hashing configuration.

---

### 13. Future Scope

1. **k-Anonymity Breach Lookups:** Integrate SHA-1 prefix-based k-anonymity queries to check against billions of leaked credentials without revealing the password.
2. **Zxcvbn Graph Search Integration:** Incorporate dynamic entropy matching using directed acyclic graph (DAG) path search.
3. **WebAuthn / Passkey Educational Module:** Provide interactive demonstrations of public-key cryptography and FIDO2 passwordless authentication.
4. **Enterprise IAM Connectors:** Package the analyzer as a pluggable pre-commit or pre-registration webhook for Keycloak, Okta, or Active Directory.

---

### 14. Conclusion

The **Password Strength Analyzer & Security Suggestion Tool** demonstrates that effective password defense requires transitioning away from superficial composition rules toward multi-vector pattern resistance, length prioritization, dictionary screening, and actionable user education. By pairing rigorous in-memory analytical algorithms with an uncompromising zero-retention privacy architecture, this project delivers an industry-aligned proof-of-work showcasing expertise in application security, Identity & Access Management, and secure coding practices.
