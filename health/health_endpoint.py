#!/usr/bin/env python3
# =============================================================================
# health_endpoint.py — Birkin Health Endpoint
# Version: 1.0.0 | Port: 9999 | Returns JSON governance status
# =============================================================================
import os
import sys
import json
import time
import sqlite3
import subprocess
from datetime import datetime, timezone
from flask import Flask, jsonify

app = Flask(__name__)

# Configuration from environment
HEALTH_HOST = os.environ.get("HEALTH_HOST", "127.0.0.1")
HEALTH_PORT = int(os.environ.get("HEALTH_PORT", "9999"))
HERMES_AUDIT_DB = os.environ.get("HERMES_AUDIT_DB", os.path.expanduser("~/.hermes/audit.db"))
HERMES_SKILLS_DIR = os.environ.get("HERMES_SKILLS_DIR", os.path.expanduser("~/.hermes/skills"))
HERMES_HOME = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))

START_TIME = time.time()


def get_hermes_status():
    """Check if Hermes gateway process is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "hermes-gateway"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except Exception:
        return False


def get_last_action_timestamp():
    """Get timestamp of most recent audit log entry."""
    try:
        conn = sqlite3.connect(HERMES_AUDIT_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(timestamp) FROM audit_log")
        result = cursor.fetchone()
        conn.close()
        if result and result[0]:
            return datetime.fromtimestamp(result[0], tz=timezone.utc).isoformat()
        return None
    except Exception:
        return None


def get_skill_count():
    """Count SKILL.md files in skills directory."""
    try:
        return len([f for f in os.listdir(HERMES_SKILLS_DIR) if f.endswith(".md")])
    except Exception:
        return 0


def get_audit_log_entries():
    """Count total audit log entries."""
    try:
        conn = sqlite3.connect(HERMES_AUDIT_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else 0
    except Exception:
        return 0


def get_drift_check_info():
    """Get latest drift check result."""
    drift_dir = os.path.join(HERMES_HOME, "drift")
    try:
        files = [f for f in os.listdir(drift_dir) if f.startswith("drift-results-") and f.endswith(".json")]
        if not files:
            return {"last_run": None, "status": "UNKNOWN"}
        latest = max(files)
        with open(os.path.join(drift_dir, latest)) as f:
            data = json.load(f)
        return {
            "last_run": data.get("timestamp"),
            "status": data.get("status", "UNKNOWN"),
            "pass_count": data.get("pass_count", 0),
            "fail_count": data.get("fail_count", 0)
        }
    except Exception:
        return {"last_run": None, "status": "ERROR"}


@app.route("/health", methods=["GET"])
def health():
    """Return comprehensive agent health status."""
    uptime_seconds = int(time.time() - START_TIME)
    hermes_running = get_hermes_status()

    status = "healthy" if hermes_running else "degraded"

    response = {
        "agent_status": status,
        "uptime_seconds": uptime_seconds,
        "last_action_timestamp": get_last_action_timestamp(),
        "skill_count": get_skill_count(),
        "audit_log_entries": get_audit_log_entries(),
        "drift_check_last_run": get_drift_check_info()["last_run"],
        "drift_check_status": get_drift_check_info()["status"],
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    http_code = 200 if status == "healthy" else 503
    return jsonify(response), http_code


@app.route("/health/detailed", methods=["GET"])
def health_detailed():
    """Return detailed health with drift breakdown."""
    base, _ = health()
    drift_info = get_drift_check_info()

    detailed = base.get_json()
    detailed["drift_check_details"] = drift_info
    detailed["governance_status"] = "intact" if drift_info["status"] == "PASS" else "review_needed"
    detailed["server_time_utc"] = datetime.now(timezone.utc).isoformat()

    return jsonify(detailed), 200


if __name__ == "__main__":
    print(f"[Health Endpoint] Starting on {HEALTH_HOST}:{HEALTH_PORT}")
    # Use threaded=True for concurrent health checks
    app.run(host=HEALTH_HOST, port=HEALTH_PORT, threaded=True)
