#!/usr/bin/env bash
# End-to-end check of `penguin-cloner vars` / `dump --vars` on a STRIPPED C program:
# no symbols, no JSON declaration -> typed dictionary must still be recovered.
set -euo pipefail
BIN=${1:-./target/release/penguin-cloner}
BIN=$(readlink -f "$BIN")
WORK=$(mktemp -d)
cd "$(dirname "$0")/.."

gcc -O0 -w -o "$WORK/t2" testdata/target2.c -lm
strip "$WORK/t2"

# The cloner must be the *parent* of the target, so Yama ptrace_scope=1 allows the attach.
run_as_parent() { # $@ = cloner arguments, PID is substituted for @PID@
  bash -c '
    "$1" >/dev/null & P=$!
    ( sleep 40; kill $P ) >/dev/null 2>&1 &
    sleep 1
    shift
    args=("${@//@PID@/$P}")
    exec "${args[@]}"
  ' _ "$WORK/t2" "$@"
}

run_as_parent "$BIN" vars --pid @PID@ --out "$WORK/v" --watch 2 --print >"$WORK/stdout" 2>"$WORK/stderr" \
  || { cat "$WORK/stderr"; exit 1; }
run_as_parent "$BIN" dump --pid @PID@ --out "$WORK/d" --vars --heap-stack-only >/dev/null 2>"$WORK/stderr2" \
  || { cat "$WORK/stderr2"; exit 1; }

diagnostics() {
  echo "---- diagnostics ----"
  gcc --version | head -1
  echo "float/double accesses in the target:"
  objdump -d --no-show-raw-insn -M intel "$WORK/t2" | grep -E "xmm" | grep -E "rip\+" || true
  python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])); print(json.dumps(d['notes'], indent=1)); print(json.dumps({k:v for k,v in d['details'].items() if k in ('g_4024','g_4028','g_4090')}, indent=1))" "$WORK/v/variables.json" || true
}
trap 'rc=$?; [ $rc -ne 0 ] && diagnostics; rm -rf "$WORK"; exit $rc' EXIT

python3 -I - "$WORK/v/variables.json" "$WORK/d/variables.json" "$WORK/stdout" <<'PY'
import json, sys
for path in sys.argv[1:3]:
    v = json.load(open(path))["variables"]
    vals = list(v.values())
    assert 512 in vals, f"{path}: int 512 missing: {v}"
    assert 2.5 in vals, f"{path}: float 2.5 missing: {v}"
    assert 3.0 in vals, f"{path}: double 3.0 missing: {v}"
    assert "legacy-01.example" in vals, f"{path}: char[] missing: {v}"
    assert "/etc/legacyd.conf" in vals, f"{path}: char* missing: {v}"
    # heap-object fields need --watch; `dump --vars` never watches (frozen process)
    if path == sys.argv[1]:
        assert "alice" in vals, f"{path}: heap struct string missing: {v}"
lines = open(sys.argv[3]).read().splitlines()
assert any(l.endswith(' = 512') for l in lines), lines
print("e2e vars OK:", len(v), "variables")
PY
