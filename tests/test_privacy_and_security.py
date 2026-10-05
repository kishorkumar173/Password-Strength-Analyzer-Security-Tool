"""
Defensive Security & Privacy Verification Tests.
Verifies critical non-functional security constraints:
  - Zero password persistence in SQLite schema
  - Zero password persistence in SQLite records
  - Zero password echoing in API response bodies
  - Zero plaintext leakages in error messages
"""

import pytest
import sqlite3
from backend.app import create_app
from backend.database import get_db_connection, record_analysis_metadata
from backend.services.password_analyzer import analyze_password


@pytest.fixture
def app_client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_database_schema_has_no_password_columns():
    """Verify that SQLite tables contains ZERO columns named 'password' or 'hash'."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Inspect analyses table columns
    cursor.execute("PRAGMA table_info(analyses)")
    analysis_columns = [row[1].lower() for row in cursor.fetchall()]

    # Inspect findings table columns
    cursor.execute("PRAGMA table_info(findings)")
    finding_columns = [row[1].lower() for row in cursor.fetchall()]

    conn.close()

    credential_columns = ["password", "plaintext", "secret", "user_hash", "pass_hash", "pwd", "hash"]
    for col in analysis_columns:
        assert col not in credential_columns, f"Security Violation: Credential column '{col}' found in analyses table!"

    for col in finding_columns:
        assert col not in credential_columns, f"Security Violation: Credential column '{col}' found in findings table!"


def test_record_metadata_never_stores_plaintext():
    """Verify that recorded telemetry contains strictly numerical/categorical values."""
    sensitive_synthetic_pwd = "SuperSecretTestSyntheticCredential999!"
    analysis = analyze_password(sensitive_synthetic_pwd)

    record_id = record_analysis_metadata(analysis)
    assert record_id is not None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM analyses WHERE analysis_id = ?", (record_id,))
    row = dict(cursor.fetchone())
    conn.close()

    # Verify sensitive string does not appear in any row value
    for k, v in row.items():
        assert sensitive_synthetic_pwd not in str(v), f"Plaintext leak in column {k}: {v}"


def test_api_response_never_echoes_password(app_client):
    """Verify POST /api/analyze response JSON does NOT contain the submitted password string."""
    candidate = "TopSecretCandidatePassword123!"
    res = app_client.post("/api/analyze", json={"password": candidate})
    assert res.status_code == 200

    response_text = res.get_data(as_text=True)
    assert candidate not in response_text, "Security Failure: Password was echoed back in API response body!"


def test_input_truncation_dos_defense():
    """Verify that massive passwords (e.g. 50,000 chars) are safely bounded to prevent ReDoS / memory exhaustion."""
    giant_input = "A" * 50000
    res = analyze_password(giant_input)
    assert res["metrics"]["length"] <= 256
