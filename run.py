"""
Root Launcher for Password Strength Analyzer & Security Suggestion Tool.
Run via:
    python run.py
"""

import sys
from pathlib import Path

# Ensure root directory is on PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.app import create_app
from backend.config import HOST, PORT, DEBUG

if __name__ == "__main__":
    app = create_app()
    print(f"\n" + "=" * 70)
    print("🔒 PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL")
    print("=" * 70)
    print("  🛡️  Zero-Knowledge Defensive Cybersecurity Project")
    print(f"  🌐 Local Dashboard: http://{HOST}:{PORT}")
    print(f"  🧪 Interactive API:  http://{HOST}:{PORT}/api/dashboard/stats")
    print("  ⚠️  Notice: Passwords are analyzed purely in-memory and never saved.")
    print("=" * 70 + "\n")
    app.run(host=HOST, port=PORT, debug=DEBUG)
