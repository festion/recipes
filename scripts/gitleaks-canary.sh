#!/usr/bin/env bash
# gitleaks CI canary — proves the secret-scan gate CAN FAIL on the
# `anthropic-api-key` rule (ops #2912). Run by .github/workflows/secret-scan.yml
# as the step after "Scan working tree", in the SAME job, with the SAME binary
# and the SAME --config as the gate.
#
# Design: operations docs/plans/2026-10-20-gitleaks-ci-canary-design.md.
#
# WHY THE VECTORS ARE BUILT AT RUNTIME. This repo has GitHub secret scanning,
# push protection and partner validity checks on, and "Anthropic API Key" is a
# partner pattern. A committed fixture would be blocked at push, or (bypassed)
# raise an alert and be sent to the vendor for validation. So nothing
# credential-shaped exists in git: the prefix is assembled from separate
# variables below, and the body is derived from a fixed documented seed via a
# base64url(sha256(seed || n)) chain. The value lives only in a mktemp dir under
# $RUNNER_TEMP for the life of this script.
#
# NEVER PRINT THE VALUE. No `set -x`, ever. Scans use --redact and
# --log-level warn; only RuleID/File/StartLine are printed from the JSON report.
# No artifacts are uploaded. Do NOT add `continue-on-error` to the step that
# runs this — a canary that cannot turn the check red is decoration.
#
# ARMS
#   positives (must be detected, rc 42, RuleID == $EXPECT_RULE, Secret REDACTED)
#     realistic-95       body 95 — the one measured live key length (ops #2874)
# FLOOR: the canary's own vectors sit at and above these floors on purpose; anything below
#   a floor is invisible to that gitleaks rule (covered by the digest watcher, ops #3995).
#     floor-20           body 20 — proves the {20,} floor; a silent revert to
#                        {90,} would still detect the 95 vector
#   negatives (must scan clean, rc 0 exactly, and the positive assertion must FAIL)
#     floor-minus-one-19 body 19
#     prefix-broken      the hyphen after the version digits replaced by a letter
#     empty-dir          the scanner was given nothing
#   exit 0 only if 2/2 positives detected and 3/3 negatives rejected.
#
# SCOPE / NAMED RESIDUALS (accepted by the operator, 2026-10-20)
#   #11  The gate step ITSELF being neutered — `continue-on-error`, `--exit-code
#        0`, `if: false`, deleted, a `paths-ignore`, or `gitleaks` dropped from
#        the ruleset's required checks — is structurally invisible to this
#        canary: it proves the scanner + config + rule, not the gate step's
#        wiring. Partial defences: same job (the required `gitleaks` check
#        covers both steps); ruleset `main` requires `gitleaks`; the drift
#        watcher's run-liveness check. The residual is REVIEW DISCIPLINE on
#        every secret-scan.yml edit.
#   #12  Per-path coverage of the real tree (a new broad path allowlist) is not
#        proven; only a tree-wide `.*` allowlist is caught (the probe goes dark).
#   .gitleaksignore is deliberately NOT passed (`-i`) to the scans here; this
#   repo has none, and the probe dir is a fresh mktemp dir.
#
# Required env: RUNNER_TEMP, GITHUB_WORKSPACE, GITLEAKS_BIN, GITLEAKS_CONFIG
# (relative to GITHUB_WORKSPACE), EXPECT_RULE.
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP unset}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE unset}"
: "${GITLEAKS_BIN:?GITLEAKS_BIN unset}"
: "${GITLEAKS_CONFIG:?GITLEAKS_CONFIG unset}"
: "${EXPECT_RULE:?EXPECT_RULE unset}"
: "${GITLEAKS_VERSION:?GITLEAKS_VERSION unset}"

work=$(mktemp -d -p "$RUNNER_TEMP" gitleaks-canary.XXXXXX)
trap 'rm -rf "$work"' EXIT

cfg="$GITHUB_WORKSPACE/$GITLEAKS_CONFIG"
test -f "$cfg" || { echo "::error::canary: config not found: $cfg"; exit 1; }
test -x "$GITLEAKS_BIN" || { echo "::error::canary: gitleaks binary not executable: $GITLEAKS_BIN"; exit 1; }

echo "canary provenance (must match the gate's binary and config):"
sha256sum "$GITLEAKS_BIN" "$cfg"
# Review on #338: provenance is ASSERTED, not just logged. GITLEAKS_VERSION is
# the workflow-level pin the install step also reads, so a bump moves both.
got_ver=$("$GITLEAKS_BIN" version 2>/dev/null | tr -d '[:space:]v')
if [ "$got_ver" != "$GITLEAKS_VERSION" ]; then
  echo "::error::canary: binary reports '${got_ver}', expected pinned ${GITLEAKS_VERSION}"; exit 1
fi
echo "gitleaks ${got_ver} (pinned)"

# Prefix pieces. Kept apart on purpose so neither this file nor the workflow
# ever holds the full prefix contiguous with a body (see header).
PFX_VENDOR="sk""-ant"
PFX_KIND="a""pi"
PFX_VER="03"
SEED="festion/stormcrow gitleaks CI canary ops-2912 rule=${EXPECT_RULE} v1"
export PFX_VENDOR PFX_KIND PFX_VER SEED

# One Python helper (stdlib only). Sub-commands:
#   gen LEN MODE OUT   write the probe file; MODE = ok | broken. Prints nothing
#                      about the value; runs the stopword/placeholder pre-check.
#   check REPORT       exit 0 = detected ($EXPECT_RULE present, every Secret is
#                      REDACTED), 1 = not detected, 3 = report missing/malformed/
#                      unredacted. Prints RuleID/File/StartLine only.
read -r -d '' PY <<'PYEOF' || true
import base64, hashlib, json, os, re, sys

def body(n):
    seed = os.environ["SEED"].encode()
    out, i = "", 0
    while len(out) < n:
        d = hashlib.sha256(seed + b"\x00" + str(i).encode()).digest()
        out += base64.urlsafe_b64encode(d).decode().rstrip("=")
        i += 1
    return out[:n]

def precheck(b, cfg):
    # Diagnostic only: a collision here would make the positive arm go dark
    # for a reason unrelated to the gate. Fail RED and say so.
    pats = [r"(?i)false", r"(?i)null$", r"(?i)^true"]  # upstream default shapes (.gitleaks.toml table)
    try:
        import tomllib
        with open(cfg, "rb") as fh:
            pats += list(tomllib.load(fh).get("allowlist", {}).get("regexes", []))
    except ModuleNotFoundError:
        print("canary: NOTE tomllib unavailable; config allowlist pre-check skipped")
    for p in pats:
        try:
            if re.search(p, b):
                print(f"::error::canary: generated body collides with allowlist pattern {p!r}; change SEED")
                sys.exit(4)
        except re.error:
            continue

cmd = sys.argv[1]
if cmd == "gen":
    n, mode, out = int(sys.argv[2]), sys.argv[3], sys.argv[4]
    b = body(n)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", b) and len(b) == n
    precheck(b, os.environ["CANARY_CFG"])
    sep = "-" if mode == "ok" else "x"
    v = os.environ["PFX_VENDOR"] + "-" + os.environ["PFX_KIND"] + os.environ["PFX_VER"] + sep + b
    with open(out, "w") as fh:
        fh.write("canary self-test line generated in CI scratch space; not a credential.\n")
        fh.write(v + "\n")
    sys.exit(0)
if cmd == "check":
    rule = os.environ["EXPECT_RULE"]
    try:
        with open(sys.argv[2]) as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"canary: report unreadable: {type(e).__name__}")
        sys.exit(3)
    if not isinstance(data, list):
        print("canary: report is not a JSON list")
        sys.exit(3)
    # Review on #338: a malformed report must CRASH as 3, never read as 1
    # ("not detected"), so a failed assertion and a broken one stay distinct.
    try:
        for f in data:
            print(f"  finding RuleID={f.get('RuleID')} File={f.get('File')} StartLine={f.get('StartLine')}")
        if not all(f.get("Secret") == "REDACTED" for f in data):
            print("canary: a finding is NOT redacted — --redact did not apply to this scan")
            sys.exit(3)
        found = any(f.get("RuleID") == rule for f in data)
    except Exception as e:  # noqa: BLE001 — any malformed shape is an instrument failure
        print(f"canary: report has an unexpected shape: {type(e).__name__}")
        sys.exit(3)
    sys.exit(0 if found else 1)
print("canary: unknown helper command"); sys.exit(2)
PYEOF
export CANARY_CFG="$cfg"

# scan DIR REPORT -> echoes gitleaks rc. 42 = findings, 0 = clean, else fatal.
# `cd DIR && --source .` so a runner work dir under /build/ or /tests/ cannot
# path-allowlist the probe.
scan() {
  local rc=0
  ( cd "$1" && "$GITLEAKS_BIN" detect --source . --no-git --config "$cfg" \
      --redact --exit-code 42 --report-format json --report-path "$2" \
      --no-banner --log-level warn ) >&2 || rc=$?
  echo "$rc"
}

pos_ok=0; neg_ok=0; failures=()

positive() {  # name len
  local name=$1 len=$2 d="$work/$1" rep="$work/$1.json" rc det=0
  mkdir "$d"
  python3 -c "$PY" gen "$len" ok "$d/probe.txt"
  rc=$(scan "$d" "$rep")
  echo "arm $name (positive): gitleaks rc=$rc"
  python3 -c "$PY" check "$rep" || det=$?
  if [ "$rc" = 42 ] && [ "$det" = 0 ]; then
    echo "arm $name: DETECTED as $EXPECT_RULE — ok"; pos_ok=$((pos_ok + 1))
  else
    echo "::error::canary arm $name: expected rc=42 and a $EXPECT_RULE finding; got rc=$rc check=$det"
    failures+=("$name")
  fi
}

negative() {  # name len|'' mode
  local name=$1 len=$2 mode=$3 d="$work/$1" rep="$work/$1.json" rc det=0
  mkdir "$d"
  [ -n "$len" ] && python3 -c "$PY" gen "$len" "$mode" "$d/probe.txt"
  rc=$(scan "$d" "$rep")
  echo "arm $name (negative): gitleaks rc=$rc"
  python3 -c "$PY" check "$rep" || det=$?
  # rc must be 0 exactly (a crash is not a negative) and the detection
  # assertion must come back "not detected" (1), not "detected" (0) and not
  # "malformed report" (3).
  if [ "$rc" = 0 ] && [ "$det" = 1 ]; then
    echo "arm $name: rejected — ok"; neg_ok=$((neg_ok + 1))
  else
    echo "::error::canary arm $name: expected rc=0 and no $EXPECT_RULE finding; got rc=$rc check=$det (vacuous or broken assertion)"
    failures+=("$name")
  fi
}

positive realistic-95 95
positive floor-20 20
negative floor-minus-one-19 19 ok
negative prefix-broken 95 broken
negative empty-dir "" ok

echo "canary summary: positives detected ${pos_ok}/2, negatives rejected ${neg_ok}/3"
if [ "$pos_ok" -ne 2 ] || [ "$neg_ok" -ne 3 ]; then
  echo "::error::gitleaks canary FAILED (arms: ${failures[*]}) — the gate cannot be shown to fail on $EXPECT_RULE"
  exit 1
fi
echo "gitleaks canary PASSED: the gate is observed to fail on $EXPECT_RULE"
