#!/usr/bin/env bash
# Birkin 60-Second Reproducible Demonstration
# Proves: policy-controlled tool execution, Ed25519 authorization receipts,
# offline cryptographic verification, and adversarial tamper detection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo "  Birkin — 60-Second Reproducible Demonstration"
echo "  Agent Authorization & Cryptographic Evidence Layer"
echo "============================================================"
echo ""

# Helper to validate that a specific python binary meets the minimum version requirement (>= 3.10)
check_python_version() {
  local py="$1"
  "$py" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null
}

# 1. Environment & Python discovery (guarantees local repository execution and validates interpreter version)
PYTHON_EXEC=""
if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ] && check_python_version "${VIRTUAL_ENV}/bin/python"; then
  PYTHON_EXEC="${VIRTUAL_ENV}/bin/python"
elif [ -d ".venv" ] && [ -x ".venv/bin/python" ] && check_python_version ".venv/bin/python"; then
  PYTHON_EXEC=".venv/bin/python"
elif [ -d "venv" ] && [ -x "venv/bin/python" ] && check_python_version "venv/bin/python"; then
  PYTHON_EXEC="venv/bin/python"
else
  # Discover compatible Python runtime (>= 3.10)
  for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && check_python_version "$candidate"; then
      PYTHON_EXEC="$candidate"
      break
    fi
  done

  if [ -z "$PYTHON_EXEC" ]; then
    echo "ERROR: Birkin requires Python >= 3.10, but none was found in PATH." >&2
    exit 1
  fi

  echo "Setting up repository virtual environment (.venv) using $PYTHON_EXEC..."
  "$PYTHON_EXEC" -m venv .venv
  PYTHON_EXEC=".venv/bin/python"
  "$PYTHON_EXEC" -m pip install --upgrade pip -q
  "$PYTHON_EXEC" -m pip install -q -e ".[dev]"
fi

# Ensure birkin package is imported from this repository
export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

run_birkin() {
  "$PYTHON_EXEC" -m receiptd.cli "$@"
}

# 2. Isolated temporary workspace for demonstration artifacts
DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/birkin-demo-XXXXXX")"
trap 'rm -rf "${DEMO_DIR}"' EXIT

DEMO_OUT="${DEMO_DIR}/run_package.json"
ATTACK1_OUT="${DEMO_DIR}/attack1_package.json"
ATTACK2_OUT="${DEMO_DIR}/attack2_package.json"
ATTACK3_CLEAN="${DEMO_DIR}/attack3_clean.json"
ATTACK3_TAMPERED="${DEMO_DIR}/run_package_tampered.json"

echo "1. Running authentic agent session through policy control plane (in-process Hermes adapter)..."
run_birkin demo --out "$DEMO_OUT"
if [ ! -s "$DEMO_OUT" ]; then
  echo "ERROR: Expected run package was not created: $DEMO_OUT" >&2
  exit 1
fi
echo ""

echo "2. Verifying package offline (zero network calls, standalone Ed25519 & hash chain)..."
run_birkin verify "$DEMO_OUT"
echo ""

echo "3. Simulating Attack 1: Smuggled prompt injection trying to execute shell.exec..."
run_birkin attack 1 --out "$ATTACK1_OUT"
echo ""

echo "4. Simulating Attack 2: Unauthorized & privilege-escalating tool use..."
run_birkin attack 2 --out "$ATTACK2_OUT"
echo ""

echo "5. Simulating Attack 3: Skill/policy ledger tampering..."
run_birkin attack 3 --out "$ATTACK3_CLEAN"
echo ""

echo "6. Asserting cryptographic verification outcomes..."

# 6A. Assert authentic run verdict
CLEAN_VERDICT="$(run_birkin verify "$DEMO_OUT" -q)"
if [ "$CLEAN_VERDICT" != "AUTHENTIC" ]; then
  echo "ERROR: Authentic run package did not produce AUTHENTIC verdict: $CLEAN_VERDICT" >&2
  exit 1
fi

# 6B. Assert Attack 1 denial receipt presence
"$PYTHON_EXEC" - <<EOF
import json, sys
with open("$ATTACK1_OUT") as f:
    pkg = json.load(f)
receipts = pkg.get("receipts", [])
deny_receipts = [r for r in receipts if r.get("decision") == "deny" and r.get("rule") == "shell.exec.deny"]
if not deny_receipts:
    print("ERROR: Attack 1 did not record expected shell.exec.deny receipt", file=sys.stderr)
    sys.exit(1)
EOF

# 6C. Assert Attack 2 policy gate decisions (deny, require_approval, allow)
"$PYTHON_EXEC" - <<EOF
import json, sys
with open("$ATTACK2_OUT") as f:
    pkg = json.load(f)
receipts = pkg.get("receipts", [])
decisions = {r.get("decision") for r in receipts}
expected = {"deny", "require_approval", "allow"}
if not expected.issubset(decisions):
    print(f"ERROR: Attack 2 did not record expected decisions {expected}, found {decisions}", file=sys.stderr)
    sys.exit(1)
EOF

# 6D. Assert Attack 3 tampering detection (clean is AUTHENTIC, tampered is TAMPERED)
if [ ! -s "$ATTACK3_TAMPERED" ]; then
  echo "ERROR: Expected tampered package was not generated: $ATTACK3_TAMPERED" >&2
  exit 1
fi

ATTACK3_CLEAN_VERDICT="$(run_birkin verify "$ATTACK3_CLEAN" -q)"
if [ "$ATTACK3_CLEAN_VERDICT" != "AUTHENTIC" ]; then
  echo "ERROR: Attack 3 clean package did not produce AUTHENTIC: $ATTACK3_CLEAN_VERDICT" >&2
  exit 1
fi

# Verification on tampered package MUST exit with non-zero code and output TAMPERED
set +e
TAMPERED_VERDICT="$(run_birkin verify "$ATTACK3_TAMPERED" -q 2>/dev/null)"
TAMPERED_EXIT_CODE=$?
set -e

if [ "$TAMPERED_EXIT_CODE" -eq 0 ] || [ "$TAMPERED_VERDICT" != "TAMPERED" ]; then
  echo "ERROR: Tampered package was not flagged as TAMPERED (exit code: $TAMPERED_EXIT_CODE, verdict: $TAMPERED_VERDICT)" >&2
  exit 1
fi

echo "   ✓ Authentic run verified: offline 9-point verification = AUTHENTIC."
echo "   ✓ Prompt injection blocked: shell.exec.deny receipt recorded and cryptographically sealed."
echo "   ✓ Privilege escalation gated: policy enforced deny, require_approval, and allow."
echo "   ✓ Tampering detected: ledger mutation flipped offline verdict to TAMPERED (exit code $TAMPERED_EXIT_CODE)."
echo ""

echo "============================================================"
echo "  ✓ Demonstration Complete"
echo "  Policy Enforced. Receipts Signed. Tampering Caught."
echo "============================================================"
