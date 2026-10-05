"""
Database Layer for Safe Aggregate Analytics.
STRICT PRIVACY POLICY:
  - ZERO PASSWORD STORAGE.
  - ZERO PASSWORD HASH STORAGE.
  - Only stores anonymous numerical and categorization metadata:
    (score, classification tier, length, pattern flags, timestamp).
  - Designed to support defensive security dashboards and educational telemetry.
"""

import sqlite3
from typing import Dict, Any, List, Optional
from pathlib import Path
from backend.config import DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    """Creates a connection to the local SQLite database."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initializes database schema.
    Explicitly verified: Schema contains NO columns for plaintext passwords,
    encrypted passwords, or password hashes.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table 1: ANALYSES (Safe Numerical Metadata Only)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
            score INTEGER NOT NULL,
            classification TEXT NOT NULL,
            password_length INTEGER NOT NULL,
            unique_character_ratio REAL NOT NULL,
            weakness_count INTEGER NOT NULL,
            theoretical_entropy REAL NOT NULL,
            effective_entropy REAL NOT NULL,
            has_sequence INTEGER NOT NULL,
            has_repetition INTEGER NOT NULL,
            has_keyboard_pattern INTEGER NOT NULL,
            is_common INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Table 2: FINDINGS (Categorical finding metadata only)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            finding_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


def record_analysis_metadata(analysis_result: Dict[str, Any]) -> Optional[int]:
    """
    Persists only safe aggregate metadata from an analysis.
    Guarantees no raw password or credential input ever enters the database.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        metrics = analysis_result.get("metrics", {})
        flags = analysis_result.get("flags", {})
        findings = analysis_result.get("findings", [])
        weakness_count = sum(1 for f in findings if f.get("type") == "WEAKNESS")

        cursor.execute("""
            INSERT INTO analyses (
                score, classification, password_length, unique_character_ratio,
                weakness_count, theoretical_entropy, effective_entropy,
                has_sequence, has_repetition, has_keyboard_pattern, is_common
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_result.get("score", 0),
            analysis_result.get("classification", "UNKNOWN"),
            metrics.get("length", 0),
            metrics.get("unique_character_ratio", 0.0),
            weakness_count,
            metrics.get("theoretical_entropy_bits", 0.0),
            metrics.get("effective_entropy_bits", 0.0),
            1 if flags.get("has_sequence") else 0,
            1 if flags.get("has_repetition") else 0,
            1 if flags.get("has_keyboard_pattern") else 0,
            1 if flags.get("is_common") else 0
        ))

        analysis_id = cursor.lastrowid

        # Insert finding metadata
        for finding in findings:
            cursor.execute("""
                INSERT INTO findings (analysis_id, finding_type, severity, title, description)
                VALUES (?, ?, ?, ?, ?)
            """, (
                analysis_id,
                finding.get("type", "UNKNOWN"),
                finding.get("severity", "INFO"),
                finding.get("title", ""),
                finding.get("description", "")
            ))

        conn.commit()
        conn.close()
        return analysis_id
    except Exception as e:
        print(f"Error persisting safe analytics metadata: {e}")
        return None


def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Aggregates anonymous telemetry for SOC / IAM style awareness dashboard.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Total Analyses
    cursor.execute("SELECT COUNT(*) AS total FROM analyses")
    total_row = cursor.fetchone()
    total_analyses = total_row["total"] if total_row else 0

    if total_analyses == 0:
        conn.close()
        return {
            "total_analyses": 0,
            "average_score": 0,
            "average_length": 0,
            "classification_counts": {
                "VERY WEAK": 0,
                "WEAK": 0,
                "MODERATE": 0,
                "STRONG": 0,
                "VERY STRONG": 0
            },
            "weakness_frequency": {
                "Known Common Password": 0,
                "Sequential Pattern": 0,
                "Keyboard Pattern": 0,
                "Repetitive Pattern": 0,
                "Short Length (<8)": 0
            },
            "score_ranges": {
                "0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0
            },
            "length_distribution": {
                "< 8": 0, "8-11": 0, "12-15": 0, "16+": 0
            },
            "recent_analyses": []
        }

    # 2. Average Score & Average Length
    cursor.execute("SELECT AVG(score) AS avg_score, AVG(password_length) AS avg_len FROM analyses")
    avg_row = cursor.fetchone()
    avg_score = round(avg_row["avg_score"] or 0, 1)
    avg_len = round(avg_row["avg_len"] or 0, 1)

    # 3. Classification Distribution
    cursor.execute("""
        SELECT classification, COUNT(*) AS count
        FROM analyses
        GROUP BY classification
    """)
    class_rows = cursor.fetchall()
    class_counts = {
        "VERY WEAK": 0,
        "WEAK": 0,
        "MODERATE": 0,
        "STRONG": 0,
        "VERY STRONG": 0
    }
    for row in class_rows:
        if row["classification"] in class_counts:
            class_counts[row["classification"]] = row["count"]

    # 4. Weakness Pattern Frequencies
    cursor.execute("""
        SELECT 
            SUM(is_common) AS common_cnt,
            SUM(has_sequence) AS seq_cnt,
            SUM(has_keyboard_pattern) AS key_cnt,
            SUM(has_repetition) AS rep_cnt
        FROM analyses
    """)
    weakness_row = cursor.fetchone()

    cursor.execute("SELECT COUNT(*) AS short_cnt FROM analyses WHERE password_length < 8")
    short_row = cursor.fetchone()

    weakness_freq = {
        "Known Common Password": weakness_row["common_cnt"] or 0,
        "Sequential Pattern": weakness_row["seq_cnt"] or 0,
        "Keyboard Pattern": weakness_row["key_cnt"] or 0,
        "Repetitive Pattern": weakness_row["rep_cnt"] or 0,
        "Short Length (<8)": short_row["short_cnt"] or 0
    }

    # 5. Score Distribution Histogram
    score_ranges = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN score <= 20 THEN 1 ELSE 0 END) AS r1,
            SUM(CASE WHEN score BETWEEN 21 AND 40 THEN 1 ELSE 0 END) AS r2,
            SUM(CASE WHEN score BETWEEN 41 AND 60 THEN 1 ELSE 0 END) AS r3,
            SUM(CASE WHEN score BETWEEN 61 AND 80 THEN 1 ELSE 0 END) AS r4,
            SUM(CASE WHEN score >= 81 THEN 1 ELSE 0 END) AS r5
        FROM analyses
    """)
    hist_row = cursor.fetchone()
    if hist_row:
        score_ranges["0-20"] = hist_row["r1"] or 0
        score_ranges["21-40"] = hist_row["r2"] or 0
        score_ranges["41-60"] = hist_row["r3"] or 0
        score_ranges["61-80"] = hist_row["r4"] or 0
        score_ranges["81-100"] = hist_row["r5"] or 0

    # 6. Length Distribution
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN password_length < 8 THEN 1 ELSE 0 END) AS l1,
            SUM(CASE WHEN password_length BETWEEN 8 AND 11 THEN 1 ELSE 0 END) AS l2,
            SUM(CASE WHEN password_length BETWEEN 12 AND 15 THEN 1 ELSE 0 END) AS l3,
            SUM(CASE WHEN password_length >= 16 THEN 1 ELSE 0 END) AS l4
        FROM analyses
    """)
    len_dist_row = cursor.fetchone()
    length_distribution = {
        "< 8": len_dist_row["l1"] or 0,
        "8-11": len_dist_row["l2"] or 0,
        "12-15": len_dist_row["l3"] or 0,
        "16+": len_dist_row["l4"] or 0
    }

    # 7. Recent safe entries (Metadata only)
    cursor.execute("""
        SELECT analysis_id, score, classification, password_length, weakness_count, created_at
        FROM analyses
        ORDER BY analysis_id DESC
        LIMIT 10
    """)
    recent_rows = cursor.fetchall()
    recent = [
        {
            "id": r["analysis_id"],
            "score": r["score"],
            "classification": r["classification"],
            "length": r["password_length"],
            "weaknesses": r["weakness_count"],
            "created_at": r["created_at"]
        }
        for r in recent_rows
    ]

    conn.close()

    return {
        "total_analyses": total_analyses,
        "average_score": avg_score,
        "average_length": avg_len,
        "classification_counts": class_counts,
        "weakness_frequency": weakness_freq,
        "score_ranges": score_ranges,
        "length_distribution": length_distribution,
        "recent_analyses": recent
    }


def seed_demo_telemetry_if_empty() -> None:
    """
    Populates synthetic demonstration analytics so the student can present
    a populated SOC dashboard immediately upon starting the project.
    Strictly uses synthetic educational scores and counts.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS count FROM analyses")
    count = cursor.fetchone()["count"]

    if count == 0:
        synthetic_records = [
            (10, "VERY WEAK", 6, 0.5, 3, 20.0, 5.0, 1, 0, 0, 1),
            (15, "VERY WEAK", 7, 0.43, 2, 25.0, 10.0, 1, 0, 0, 1),
            (28, "WEAK", 10, 0.8, 2, 45.0, 25.0, 0, 0, 1, 0),
            (35, "WEAK", 12, 0.65, 2, 55.0, 32.0, 0, 0, 0, 1),
            (48, "MODERATE", 11, 0.9, 1, 62.0, 48.0, 0, 0, 0, 0),
            (55, "MODERATE", 13, 0.85, 1, 75.0, 55.0, 0, 1, 0, 0),
            (72, "STRONG", 15, 0.93, 0, 95.0, 78.0, 0, 0, 0, 0),
            (78, "STRONG", 16, 0.88, 0, 102.0, 85.0, 0, 0, 0, 0),
            (88, "VERY STRONG", 20, 0.95, 0, 130.0, 115.0, 0, 0, 0, 0),
            (95, "VERY STRONG", 24, 0.96, 0, 158.0, 145.0, 0, 0, 0, 0)
        ]
        cursor.executemany("""
            INSERT INTO analyses (
                score, classification, password_length, unique_character_ratio,
                weakness_count, theoretical_entropy, effective_entropy,
                has_sequence, has_repetition, has_keyboard_pattern, is_common
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, synthetic_records)
        conn.commit()

    conn.close()


def reset_analytics_data() -> None:
    """Clears all analytics data for a clean test run."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    cursor.execute("DELETE FROM analyses")
    conn.commit()
    conn.close()
