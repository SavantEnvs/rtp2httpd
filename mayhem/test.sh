#!/usr/bin/env bash
#
# mayhem/test.sh — runs the known-answer selftest (mayhem/selftest.c) that mayhem/build.sh linked against
# the project's own sources with normal flags. exit 0 = pass. The upstream e2e suite needs a live network
# stack (scapy, root), so it is not used here.
#
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

bin="$SRC/build-test/selftest"
if [ ! -x "$bin" ]; then
  echo "missing $bin — mayhem/build.sh should have built it" >&2
  emit_ctrf "rtp2httpd-selftest" 0 1 0
  exit $?
fi

out="$("$bin" 2>&1)"; rc=$?
printf '%s\n' "$out"
summary="$(printf '%s\n' "$out" | grep -E '^SELFTEST total=[0-9]+ passed=[0-9]+ failed=[0-9]+$' | tail -n1)"
if [ -z "$summary" ]; then
  echo "selftest produced no SELFTEST summary line (rc=$rc)" >&2
  emit_ctrf "rtp2httpd-selftest" 0 1 0
  exit $?
fi
passed="$(sed -E 's/.* passed=([0-9]+) .*/\1/' <<<"$summary")"
failed="$(sed -E 's/.* failed=([0-9]+)$/\1/' <<<"$summary")"
[ "$rc" -eq 0 ] || failed=$(( failed + 1 ))
emit_ctrf "rtp2httpd-selftest" "$passed" "$failed" 0
