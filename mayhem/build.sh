#!/usr/bin/env bash
#
# mayhem/build.sh — build rtp2httpd's libFuzzer harnesses (sanitized, plus -standalone reproducers)
# and the normal-flags selftest used by mayhem/test.sh. Air-gapped: the project has no dependencies
# beyond libc, so nothing is fetched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

HARNESSES="fuzz_rtp_payload fuzz_chunked_decoder fuzz_stun_response fuzz_http_request fuzz_url_components
fuzz_m3u_rewrite fuzz_m3u_parse fuzz_url_template fuzz_service_url"

# The daemon's own sources (CMakeLists.txt COMMON_SOURCES + the Linux poller). Its main() is renamed
# so the harness's engine or the selftest supplies the entry point (applied in compile_tree).
SOURCES="$(ls src/*.c src/vendor/*/*.c | grep -v -e '/poller_kqueue\.c$')"
DEFS=(-D_GNU_SOURCE '-DSYSCONFDIR="/etc"' '-DPACKAGE="rtp2httpd"' '-DVERSION="1.0.0-fuzz"' -Isrc)

# compile_tree <outdir> <flags...>: one object per source, then a static archive.
compile_tree() {
  local out="$1"; shift
  rm -rf "$out"; mkdir -p "$out"
  for f in $SOURCES; do
    printf '%s\n' "$f"
  done | xargs -P "$MAYHEM_JOBS" -I{} sh -c '
      out="$1"; src="$2"; shift 2
      o="$out/$(echo "$src" | tr / _).o"
      "$@" -c "$src" -o "$o"' _ "$out" {} "$CC" "$@" "${DEFS[@]}" -std=gnu11 -Dmain=rtp2httpd_unused_main
  # shellcheck disable=SC2046
  llvm-ar rcs "$out/libproject.a" "$out"/*.o
}

# 1) The project with sanitizers + libFuzzer coverage instrumentation.
compile_tree "$SRC/build-fuzz" $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SRC/build-fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "$SRC/mayhem/numeric_getaddrinfo.c" -o "$SRC/build-fuzz/numeric_getaddrinfo.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build-fuzz/standalone_main.o"

# 2) Each harness, linked against libFuzzer and against the run-once standalone driver.
for h in $HARNESSES; do
  $CC $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -std=gnu11 "${DEFS[@]}" -c \
      "$SRC/mayhem/harnesses/$h.c" -o "$SRC/build-fuzz/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/build-fuzz/$h.o" "$SRC/build-fuzz/libproject.a" \
      "$SRC/build-fuzz/lsan_off.o" "$SRC/build-fuzz/numeric_getaddrinfo.o" -lm -lpthread -lrt -o "/mayhem/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$SRC/build-fuzz/standalone_main.o" "$SRC/build-fuzz/$h.o" \
      "$SRC/build-fuzz/libproject.a" "$SRC/build-fuzz/lsan_off.o" "$SRC/build-fuzz/numeric_getaddrinfo.o" -lm -lpthread -lrt -o "/mayhem/$h-standalone"
done

# 3) The project with its normal flags (no sanitizers) + the selftest that mayhem/test.sh runs.
# shellcheck disable=SC2086
compile_tree "$SRC/build-test" -O2 $COVERAGE_FLAGS
# shellcheck disable=SC2086
$CC -O2 $COVERAGE_FLAGS -std=gnu11 "${DEFS[@]}" "$SRC/mayhem/selftest.c" "$SRC/build-test/libproject.a" \
    -lm -lpthread -lrt -o "$SRC/build-test/selftest"
