"""
Root Launcher for Password Strength Analyzer & Security Suggestion Tool.
Run via:
    python run.py
"""

import os
import sys
from pathlib import Path

# Ensure root directory is on PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.app import create_app

if __name__ == "__main__":
    app = create_app()
    # Cloud platforms (Render, Railway, Heroku) inject PORT into env
    port = int(os.environ.get("PORT", 5000))
    # Must bind to 0.0.0.0 for external cloud load balancers to reach the app
    host = "0.0.0.0"
    debug = os.environ.get("DEBUG", "False").lower() == "true"

    print(f"\n" + "=" * 70)
    print("🔒 PASSWORD STRENGTH ANALYZER & SECURITY SUGGESTION TOOL")
    print("=" * 70)
    print("  🛡️  Zero-Knowledge Defensive Cybersecurity Project")
    print(f"  🌐 Server Listening On: http://{host}:{port}")
    print(f"  🧪 Interactive API:     http://{host}:{port}/api/dashboard/stats")
    print("  ⚠️  Notice: Passwords are analyzed purely in-memory and never saved.")
    print("=" * 70 + "\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
