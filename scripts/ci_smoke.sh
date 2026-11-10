#!/usr/bin/env bash
# scripts/ci_smoke.sh
#
# The CI smoke gate for Birkin.
#
# This script is the *single source of truth* for "does the vertical slice
# still hold?" If it exits non-zero, the release is red. No exceptions.
#
# What it checks (in order, fail-fast):
#
#   1. The full test suite passes.
#   2. `birkin demo` produces VERDICT: AUTHENTIC.
#   3. `birkin verify` (offline) on the exported package is AUTHENTIC.
#   4. `birkin attack 1` (prompt injection) is blocked + AUTHENTIC.
#   5. `birkin attack 2` (privilege escalation) is blocked + AUTHENTIC.
#   6. `birkin attack 3` (tampering) shows BOTH a clean AUTHENTIC and
#      a tampered TAMPERED package side by side.
#   7. The NullAgent second-adapter proof runs through the same engine
#      and verifies AUTHENTIC.
#
# The script is intentionally verbose: every step prints a banner and
# exits non-zero on the first failure. CI logs should be readable.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d -t birkin-ci-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0

banner() {
    echo
    echo "=================================================================="
    echo "  $1"
    echo "=================================================================="
}

step() {
    echo "  --> $1"
}

ok() {
    echo "  [OK] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
    echo "  >>> $2"
    exit 1
}

# --------------------------------------------------------------------------- #
banner "BIRKIN CI SMOKE GATE"
echo "  work dir: $WORK"
echo "  root:     $ROOT"
# --------------------------------------------------------------------------- #

# --- 1. Test suite --------------------------------------------------------- #
banner "1. pytest tests/"
if python3 -m pytest tests/ -q >/tmp/pytest.log 2>&1; then
    ok "test suite passes"
    tail -3 /tmp/pytest.log | sed 's/^/      /'
else
    fail "test suite failed" "$(tail -30 /tmp/pytest.log)"
fi

# --- 2. birkin demo -> AUTHENTIC ------------------------------------------ #
banner "2. birkin demo -> VERDICT: AUTHENTIC"
DEMO_PKG="$WORK/demo.json"
step "running birkin demo --out $DEMO_PKG"
if python3 -m receiptd.cli demo --out "$DEMO_PKG" >"$WORK/demo.out" 2>&1; then
    if grep -q "VERDICT: AUTHENTIC" "$WORK/demo.out"; then
        ok "birkin demo produces AUTHENTIC"
    else
        fail "birkin demo did not produce AUTHENTIC" "$(cat "$WORK/demo.out")"
    fi
else
    fail "birkin demo crashed" "$(cat "$WORK/demo.out")"
fi

# --- 3. birkin verify (offline) ------------------------------------------- #
banner "3. birkin verify $DEMO_PKG (offline, no server)"
step "verifying exported package"
if python3 -m receiptd.cli verify "$DEMO_PKG" >"$WORK/verify.out" 2>&1; then
    if grep -q "VERDICT: AUTHENTIC" "$WORK/verify.out"; then
        ok "offline verify = AUTHENTIC"
        sed 's/^/      /' "$WORK/verify.out"
    else
        fail "verify did not return AUTHENTIC" "$(cat "$WORK/verify.out")"
    fi
else
    fail "birkin verify exited non-zero" "$(cat "$WORK/verify.out")"
fi

# --- 4. attack 1: prompt injection ---------------------------------------- #
banner "4. birkin attack 1 (prompt injection / goal hijacking)"
if python3 -m receiptd.cli attack 1 --out "$WORK/attack1.json" >"$WORK/attack1.out" 2>&1; then
    if grep -q "decision=deny" "$WORK/attack1.out" && grep -q "VERDICT: AUTHENTIC" "$WORK/attack1.out"; then
        ok "attack 1 blocked + AUTHENTIC"
        grep -E "decision=|VERDICT" "$WORK/attack1.out" | sed 's/^/      /'
    else
        fail "attack 1 did not produce deny + AUTHENTIC" "$(cat "$WORK/attack1.out")"
    fi
else
    fail "attack 1 crashed" "$(cat "$WORK/attack1.out")"
fi

# --- 5. attack 2: privilege escalation ----------------------------------- #
banner "5. birkin attack 2 (privilege escalation)"
if python3 -m receiptd.cli attack 2 --out "$WORK/attack2.json" >"$WORK/attack2.out" 2>&1; then
    if grep -q "decision=deny" "$WORK/attack2.out" \
       && grep -q "decision=require_approval" "$WORK/attack2.out" \
       && grep -q "VERDICT: AUTHENTIC" "$WORK/attack2.out"; then
        ok "attack 2: deny + require_approval + allow, AUTHENTIC"
        grep -E "decision=|VERDICT" "$WORK/attack2.out" | sed 's/^/      /'
    else
        fail "attack 2 missing one of {deny, require_approval, allow, AUTHENTIC}" \
             "$(cat "$WORK/attack2.out")"
    fi
else
    fail "attack 2 crashed" "$(cat "$WORK/attack2.out")"
fi

# --- 6. attack 3: tamper detection (clean AUTHENTIC + tampered TAMPERED) - #
banner "6. birkin attack 3 (tamper detection — clean AUTHENTIC + tampered TAMPERED)"
if python3 -m receiptd.cli attack 3 --out "$WORK/attack3.json" >"$WORK/attack3.out" 2>&1; then
    if grep -q "VERDICT: AUTHENTIC" "$WORK/attack3.out" \
       && grep -q "VERDICT: TAMPERED" "$WORK/attack3.out"; then
        ok "attack 3: clean=AUTHENTIC, tampered=TAMPERED"
        grep -E "VERDICT|TAMPERED|AUTHENTIC" "$WORK/attack3.out" | sed 's/^/      /'
    else
        fail "attack 3 did not show both AUTHENTIC and TAMPERED" \
             "$(cat "$WORK/attack3.out")"
    fi
else
    fail "attack 3 crashed" "$(cat "$WORK/attack3.out")"
fi

# --- 7. NullAgent second-adapter proof ------------------------------------ #
banner "7. NullAgent second-adapter proof (same engine, same verifier)"
step "running NullAgent through Birkin + verify_package"
if python3 -c "
import sys; sys.path.insert(0, '$ROOT')
from receiptd import Engine, NullAgentAdapter, SigningKey, load_default_policy, verify_package
sk = SigningKey.generate()
p = load_default_policy()
adapter = NullAgentAdapter()
e = Engine(birkin_signing_key=sk, policy=p, adapter=adapter)
ident = adapter.make_identity(agent_id='ci-null-agent', policy_ref=p.ref)
e.start_session(ident)
e.declare_intent(ident, adapter.declare_intent(ident, 'CI: prove the AgentAdapter seam'))
req = adapter.build_action_request(tool='null.ping', args={'echo': 'ci'})
r = e.attempt_action(ident, req)
assert r.decision == 'allow', r.reason
e.execute(ident, req, r)
e.checkpoint()
e.end_session(ident)
pkg = e.export(identity=ident)
report = verify_package(pkg)
print('  verdict:', report.verdict)
assert report.verdict == 'AUTHENTIC'
" >"$WORK/null.out" 2>&1; then
    if grep -q "AUTHENTIC" "$WORK/null.out"; then
        ok "NullAgent seam: AUTHENTIC via same engine + verifier"
        sed 's/^/      /' "$WORK/null.out"
    else
        fail "NullAgent did not produce AUTHENTIC" "$(cat "$WORK/null.out")"
    fi
else
    fail "NullAgent proof crashed" "$(cat "$WORK/null.out")"
fi

# --------------------------------------------------------------------------- #
banner "BIRKIN CI SMOKE GATE — PASSED"
echo "  $PASS checks passed, $FAIL failed."
echo "  Release is GREEN."
echo "=================================================================="
exit 0
