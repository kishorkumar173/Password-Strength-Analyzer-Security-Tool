# System Architecture & Technical Specifications

## Architectural Overview

The **Password Strength Analyzer & Security Suggestion Tool** is architected as a lightweight, zero-knowledge defensive cybersecurity application. It enforces a strict separation between ephemeral password evaluation and persistent aggregate telemetry.

```
                        +---------------------------+
                        |      End-User Client      |
                        | (Browser DOM & JS Engine) |
                        +---------------------------+
                                      │
                         HTTP POST /api/analyze (JSON)
                                      ▼
                        +---------------------------+
                        |       Flask API Gateway   |
                        | - Werkzeug Logging Off    |
                        | - Security Response Hdrs  |
                        +---------------------------+
                                      │
                             In-Memory Dispatch
                                      ▼
             +──────────────────────────────────────────────────+
             |         Master Password Analyzer Engine          |
             +──────────────────────────────────────────────────+
              ├── Length Analyzer
              ├── Character Diversity & Uniqueness Analyzer
              ├── Common Password & Leetspeak Checker
              ├── Sequence Detector (Numeric & Alphabetical)
              ├── Keyboard Pattern Detector (Horizontal Walks)
              ├── Repetition & Substring Cycle Detector
              ├── Predictable Structure Detector (Year, TitleCase)
              ├── Personal Context Checker (OSINT Defense)
              ├── Entropy Estimator (Theoretical vs Effective)
              ├── Composite Strength Scoring Engine
              └── Remediation & Suggestion Engine
                         │                           │
          Structured Analysis Result        Anonymous Telemetry
                         │                           │
                         ▼                           ▼
            +─────────────────────────+  +─────────────────────────+
            | Client UI & Meter View  |  |    SQLite Analytics     |
            | (Gauges, Cards, Badges) |  |   (Zero Credential DB)  |
            +─────────────────────────+  +─────────────────────────+
```

## Defensive Constraints Matrix

| Constraint | Implementation Mechanism | Verification |
| :--- | :--- | :--- |
| **Zero Plaintext Persistence** | SQLite schema contains NO columns for passwords. | Tested in `test_privacy_and_security.py` |
| **Zero Plaintext Logging** | Werkzeug log level set to WARNING; request bodies omitted. | Verified via stdout inspection |
| **No External Calls** | Local wordlists and mathematical algorithms only. | Operates in air-gapped environments |
| **Anti-DoS Input Bounding** | Inputs bounded to max 256 characters. | Tested with 50,000 character payload |
| **Constant-Time Verification** | `hmac.compare_digest` used for hash verification. | Mitigates timing side-channel attacks |
