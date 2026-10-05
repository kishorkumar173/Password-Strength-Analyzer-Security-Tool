# Screenshot & Visual Proof Checklist

This document details the recommended 28 visual proofs for GitHub documentation, LinkedIn portfolio posts, and academic evaluation.

| # | File Name | Target Screen / Component | Educational & Security Purpose |
| :-: | :--- | :--- | :--- |
| **01** | `01_project_folder_structure.png` | VS Code / Terminal file tree | Demonstrates clean modular architecture (`backend/`, `frontend/`, `tests/`, `data/`, `docs/`). |
| **02** | `02_architecture_diagram.png` | Architecture Flowchart | Shows in-memory data flow, separation of concerns, and the privacy barrier. |
| **03** | `03_analyzer_homepage.png` | Full Browser View | Professional dark-theme SOC / IAM dashboard layout. |
| **04** | `04_hidden_password_field.png` | Password Input Box | Demonstrates password masking (`type="password"`) and eye toggle functionality. |
| **05** | `05_very_weak_evaluation.png` | Result for `123456` | Shows red tier, score 0/100, common password and sequence alerts. |
| **06** | `06_weak_evaluation.png` | Result for `Password123!` | Proves that satisfying character classes still flags as weak due to predictability. |
| **07** | `07_moderate_evaluation.png` | Result for `Winter-Orchestra-88` | Demonstrates moderate tier with good length but predictable components. |
| **08** | `08_strong_evaluation.png` | Result for `correct-horse-battery-staple` | Validates Diceware passphrase resilience (Score 75+). |
| **09** | `09_very_strong_evaluation.png` | Result for `J9#mK$2vL@8zP&4w` | Shows emerald green tier (95/100) with zero pattern deductions. |
| **10** | `10_length_analysis_bands.png` | Length Analysis Card | Highlights educational bands (<8, 8-11, 12-15, 16+) and search space metrics. |
| **11** | `11_sequence_detection.png` | Sequential Pattern Findings | Highlights detection of ascending (`1234`) and descending (`4321`) sequences. |
| **12** | `12_keyboard_walk_detection.png` | Keyboard Pattern Findings | Flags QWERTY horizontal walks (`qwerty`, `asdfgh`, reverse walks). |
| **13** | `13_repetition_detection.png` | Repetition Findings | Demonstrates flags for consecutive identical chars (`aaaa`) and cyclic substrings. |
| **14** | `14_common_password_warning.png` | Critical Alert Banner | Displays *"Your password matches a commonly used password pattern"*. |
| **15** | `15_security_recommendations.png` | Remediation Cards | Shows specific, actionable advice (MFA, password managers, removal of patterns). |
| **16** | `16_entropy_explanation.png` | Entropy Box | Highlights theoretical bits vs. pattern-penalized effective bits. |
| **17** | `17_password_generator.png` | Generator Tab | Displays CSPRNG secrets generator with custom sliders and copy toast. |
| **18** | `18_diceware_passphrase_gen.png` | Passphrase Generator | Shows Diceware multi-word generation with estimated bits of entropy. |
| **19** | `19_policy_checker_pass.png` | Policy Tab | Evaluates password meeting NIST SP 800-63B standards (PASS). |
| **20** | `20_policy_checker_fail.png` | Policy Tab | Displays violation of minimum length or common dictionary rules (FAIL). |
| **21** | `21_hashing_lab_comparison.png` | Hashing Sandbox Tab | Side-by-side execution of fast SHA-256 vs. salted PBKDF2 with timings. |
| **22** | `22_salt_and_stretching_proof.png` | Cryptographic Output | Displays 16-byte random salt in hex and storage string format. |
| **23** | `23_analytics_dashboard_kpis.png` | Analytics Tab | Shows Total Analyses, Average Score, Average Length, and High-Risk Rate. |
| **24** | `24_analytics_charts_grid.png` | Chart.js Visualizations | Displays Doughnut, Horizontal Bar, and Score Histogram charts. |
| **25** | `25_database_schema_no_passwords.png` | SQLite CLI / DB Browser | Proves `PRAGMA table_info(analyses)` has NO password or hash column. |
| **26** | `26_30_automated_tests_pass.png` | Terminal Output | Shows all 30 automated test scenarios executing with `[PASS]` status. |
| **27** | `27_pytest_suite_pass.png` | Terminal Output | Shows `pytest tests/` passing with 100% green coverage. |
| **28** | `28_github_repository_readme.png` | GitHub Web UI | Final preview of repository, badges, commit history, and README. |
