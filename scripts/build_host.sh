#!/usr/bin/env bash
# build_host.sh — the HOST build: the correctness tests and the two CLI tools.
#
# It builds NO library. libwbcrypto.a is an Android artifact and comes only from
# scripts/build_android.sh; there is no host copy to confuse with the shipped one.
#
# WHY THE OUTPUT DIR IS `build/` AND NOT `build-host/`, despite the name: the
# `build-host/` tree belongs to scripts/gen_blob.sh, and that path is part of the
# consumer contract — native-lib-encryption points SOPACK_WBKEYGEN at
# $WBC/build-host/wb_keygen. The two must also NOT share a tree, because they use
# different toolchains on purpose: gen_blob.sh refuses $ZIG_BIN/$EXTRA_CXXFLAGS and
# picks a native compiler so no cross toolchain or O-MVLL plugin can leak into a
# provisioning tool, and it keys its libsodium cache to compiler+platform to catch
# exactly that mixing. So the asymmetry is deliberate — do not "tidy" it.
#
# No system cmake/make is assumed. A C++17 compiler is discovered in this order:
#   1. $ZIG_BIN (path to a `zig` binary; drives both `zig c++` and `zig ar`)
#   2. $CXX if set
#   3. system c++ / g++ / clang++
#   4. a Zig toolchain: `zig` on PATH, or ./toolchain/zig-*/zig
# Usage:
#   ./scripts/build_host.sh            # build the tools and all tests
#   ./scripts/build_host.sh test       # the above, then run every test
#   ZIG_BIN=/path/to/zig ./scripts/build_host.sh test
set -euo pipefail
# Every path below is repo-root-relative, so anchor there rather than at $PWD.
cd "$(dirname "$0")/.."

# ---- discover compiler + archiver -----------------------------------------
CXXCMD=(); ARCMD=()
if [ -n "${ZIG_BIN:-}" ]; then
    CXXCMD=("$ZIG_BIN" c++); ARCMD=("$ZIG_BIN" ar)
elif [ -n "${CXX:-}" ]; then
    CXXCMD=("$CXX")
else
    for c in c++ g++ clang++; do
        if command -v "$c" >/dev/null 2>&1; then CXXCMD=("$c"); break; fi
    done
    if [ ${#CXXCMD[@]} -eq 0 ]; then
        if command -v zig >/dev/null 2>&1; then CXXCMD=(zig c++); ARCMD=(zig ar)
        else
            z=$(ls -d ./toolchain/zig-*/zig 2>/dev/null | head -1 || true)
            [ -n "$z" ] && { CXXCMD=("$z" c++); ARCMD=("$z" ar); }
        fi
    fi
fi
if [ ${#CXXCMD[@]} -eq 0 ]; then
    echo "ERROR: no C++ compiler found (set ZIG_BIN or CXX)." >&2; exit 1
fi
# Archiver fallback if not already set by the zig path.
# On macOS prefer Apple's /usr/bin/ar EXPLICITLY rather than letting a Homebrew
# binutils/LLVM `ar` win on PATH: it must pair with Apple's `ld`, and a mismatch
# surfaces much later, at link time, as an opaque archive error such as
#   ld: archive member invalid control bits in '…/libsodium.a'
# Set ZIG_BIN (or edit here) if you deliberately want a different archiver.
if [ ${#ARCMD[@]} -eq 0 ]; then
    if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/ar ]; then ARCMD=(/usr/bin/ar)
    elif command -v llvm-ar >/dev/null 2>&1; then ARCMD=(llvm-ar)
    elif command -v ar >/dev/null 2>&1; then ARCMD=(ar)
    elif command -v zig >/dev/null 2>&1; then ARCMD=(zig ar); fi
fi

# A plain C compiler for the C example (falls back to the C++ driver).
if [ -n "${ZIG_BIN:-}" ]; then CCCMD=("$ZIG_BIN" cc)
elif [ -n "${CC:-}" ]; then CCCMD=("$CC")
elif command -v cc >/dev/null 2>&1; then CCCMD=(cc)
else CCCMD=("${CXXCMD[@]}"); fi

# Output directory. Overridable so a second toolchain (or an A/B of compiler
# flags) can build alongside an existing tree instead of clobbering it.
BUILD="${BUILD_DIR:-build}"
mkdir -p "$BUILD"

# ---- vendored libsodium (seal KDF + AEAD) ----------------------------------
# The runtime library links libsodium for Argon2id + XChaCha20-Poly1305. The
# source is fetched (not committed) by third_party/fetch_deps.sh — auto-run here
# so a fresh checkout never has to remember it.
SODIUM_VER="1.0.20"
SODIUM_ROOT="third_party/libsodium/libsodium-${SODIUM_VER}"
SODIUM_INC="$SODIUM_ROOT/src/libsodium/include"
if [ ! -f "$SODIUM_INC/sodium.h" ]; then
    ./third_party/fetch_deps.sh libsodium
fi
if [ ! -f "$SODIUM_INC/sodium.h" ]; then
    echo "ERROR: libsodium still missing after fetch; run ./third_party/fetch_deps.sh libsodium" >&2
    exit 1
fi

# Symbol hygiene: hide everything by default so only the wbc_* C ABI (marked
# visibility("default") in wbcrypto.h) and, via the version script below, the
# public surface end up exported. -ffunction/data-sections lets --gc-sections
# drop dead code from the shipped .so.
# Optimization level. -O2 is the default because it is what this script has
# always used and -O3 was measured to make no difference to the VM hot path (the
# per-instruction decode is a serial dependency chain, so it is latency-bound and
# there is nothing for the extra passes to win). The CMake/NDK path gets -O3 from
# its toolchain file; that mismatch does NOT contaminate the on-device A/B, which
# builds both sides through CMake. Override for flag experiments:
#   OPT_LEVEL=-O3 ./scripts/build_host.sh
OPT_LEVEL="${OPT_LEVEL:--O2}"
INCS=(-Isrc -Iinclude -Itests "-I$SODIUM_INC")
CXXFLAGS=(-std=c++17 "$OPT_LEVEL" "${INCS[@]}" -Wall -Wextra -Wno-nullability-completeness
          -fvisibility=hidden -fvisibility-inlines-hidden
          -ffunction-sections -fdata-sections)

# Host-path hygiene, mirroring CMakeLists.txt. This path leaks nothing today: it
# passes no -g and compiles through relative paths, so neither DWARF nor the
# __FILE__ strings in libsodium's asserts (this build sets no NDEBUG) carry an
# absolute path. The map is here so the two build paths do not drift, and so that
# EXTRA_CXXFLAGS="-g" — or an OPT_LEVEL carrying it — cannot quietly start
# recording $PWD. Probed, not assumed: this script accepts whatever compiler it
# discovers above, and the flag needs clang 10+ / gcc 8+.
PATHMAP=()
_probe='int main(void){return 0;}'
if echo "$_probe" | "${CXXCMD[@]}" -x c++ "-ffile-prefix-map=$PWD=." -c -o /dev/null - 2>/dev/null \
   && echo "$_probe" | "${CCCMD[@]}" -x c "-ffile-prefix-map=$PWD=." -c -o /dev/null - 2>/dev/null
then
    PATHMAP=("-ffile-prefix-map=$PWD=.")
    CXXFLAGS+=("${PATHMAP[@]}")
fi

# Opt-in native-code obfuscation hook. Append extra compiler flags (e.g. an
# LLVM pass-plugin like O-MVLL: EXTRA_CXXFLAGS="-fpass-plugin=/path/OMVLL.so").
# Empty by default, so normal builds are unaffected. See docs/BUILD.md.
#   EXTRA_CXXFLAGS  — appended to every C++ compile
#   EXTRA_LDFLAGS   — appended to every link (e.g. -Wl,-z,muldefs, which
#                     tolerates the duplicate EH-helper symbols O-MVLL can emit)
# Note: this is a HOST build. An LLVM pass-plugin requires a clang whose version
# matches the plugin (not AppleClang, not necessarily zig's clang). The fully
# tested O-MVLL path is the CMake + Android NDK cross-compile in docs/BUILD.md,
# not this script. There is no EXTRA_CFLAGS: the only C compiled here is
# libsodium, which is a dependency rather than code we obfuscate.
read -r -a EXTRA_CXX_ARR <<< "${EXTRA_CXXFLAGS:-}"
read -r -a EXTRA_LD_ARR <<< "${EXTRA_LDFLAGS:-}"
# NB: macOS ships bash 3.2, where expanding an EMPTY array as "${a[@]}" under
# `set -u` errors ("unbound variable"). Guard every possibly-empty EXTRA_* array
# expansion below with a length check or the ${a[@]+"${a[@]}"} idiom.
if [ ${#EXTRA_CXX_ARR[@]} -gt 0 ]; then CXXFLAGS+=("${EXTRA_CXX_ARR[@]}"); fi

# O-MVLL status banner: ON only if a pass-plugin was injected via EXTRA_CXXFLAGS.
case "${EXTRA_CXXFLAGS:-}" in
    *-fpass-plugin=*)
        plugin="${EXTRA_CXXFLAGS#*-fpass-plugin=}"; plugin="${plugin%% *}"
        echo "==> O-MVLL obfuscation: ON  (-fpass-plugin=$plugin)" ;;
    *)
        echo "==> O-MVLL obfuscation: OFF (set EXTRA_CXXFLAGS=-fpass-plugin=/path/plugin to enable)" ;;
esac
[ -n "${EXTRA_CXXFLAGS:-}${EXTRA_LDFLAGS:-}" ] && echo "obfuscation flags: cxx='${EXTRA_CXXFLAGS:-}' ld='${EXTRA_LDFLAGS:-}'"

# The two sets below are kept SEPARATE even though this script links their union
# into every binary, because that split is the shipped-surface invariant: only
# RUNTIME_SRCS goes into libwbcrypto.a (see CMakeLists.txt, which builds the
# archive), and wbc_seal_key must never appear in it. Keeping the lists here in the
# same shape makes a drift between the two build systems visible.
#
# RUNTIME set: field-side only — open a sealed blob, wrap/unwrap a key.
# Deliberately excludes the reference AES, the white-box generator and the
# bytecode assembler.
RUNTIME_SRCS=(
    src/vm/vm.cpp src/vm/handlers.cpp
    src/storage/trusted_storage.cpp
    src/sdk/wbcrypto.cpp
)
# PROVISIONING set: key-generation surface. Host-side only (wb_keygen and the
# tests); MUST NOT ship in the runtime library.
PROVISION_SRCS=(
    src/wbaes/gf256.cpp src/wbaes/aes_ref.cpp src/wbaes/aes_tables.cpp
    src/wbaes/encodings.cpp src/wbaes/wb_generator.cpp src/wbaes/wb_interp.cpp
    src/vm/assembler.cpp
    src/fw/fwcrypt.cpp
    src/obf/blinding.cpp
    src/sdk/wbcrypto_provision.cpp
)
RUNTIME=(); for s in "${RUNTIME_SRCS[@]}"; do [ -f "$s" ] && RUNTIME+=("$s"); done
PROVISION=(); for s in "${PROVISION_SRCS[@]}"; do [ -f "$s" ] && PROVISION+=("$s"); done
FULL=("${RUNTIME[@]}" "${PROVISION[@]}")

echo "compiler: ${CXXCMD[*]}"
echo "archiver: ${ARCMD[*]:-<none>}"

# ---- build libsodium once into build/libsodium.a ---------------------------
# Compiled with no autotools config, so only portable C is selected (the HAVE_*
# feature macros are absent). version.h is dropped in by the fetch script.
SODIUM_A="$BUILD/libsodium.a"
if [ ! -f "$SODIUM_A" ] && [ ${#ARCMD[@]} -ne 0 ]; then
    echo "build dep: libsodium ${SODIUM_VER} (portable, one-time)"
    mkdir -p "$BUILD/sodium"
    SOBJS=()
    while IFS= read -r c; do
        o="$BUILD/sodium/$(echo "$c" | tr '/.' '__').o"
        # PATHMAP is repeated here deliberately: EXTRA_CXXFLAGS does not reach
        # this compile, so the libsodium objects would otherwise miss the map.
        "${CCCMD[@]}" -O2 -fPIC -fvisibility=hidden -DCONFIGURED=1 \
            ${PATHMAP[@]+"${PATHMAP[@]}"} \
            -I"$SODIUM_INC" -I"$SODIUM_INC/sodium" -c "$c" -o "$o"
        SOBJS+=("$o")
    done < <(find "$SODIUM_ROOT/src/libsodium" -name '*.c' | sort)
    "${ARCMD[@]}" rcs "$SODIUM_A" "${SOBJS[@]}"
fi

build_bin() {  # build_bin <out> <main.cpp> -- links the FULL src set (host-only)
    local out="$1"; shift
    "${CXXCMD[@]}" "${CXXFLAGS[@]}" "$@" "${FULL[@]}" "$SODIUM_A" \
        ${EXTRA_LD_ARR[@]+"${EXTRA_LD_ARR[@]}"} -o "$BUILD/$out"
}

# ---- tests + tools ---------------------------------------------------------
TESTS=(); for t in tests/test_*.cpp; do [ -f "$t" ] && TESTS+=("$t"); done
TOOLS=(); for t in src/tools/*.cpp; do [ -f "$t" ] && TOOLS+=("$t"); done

for t in "${TESTS[@]}"; do
    name=$(basename "$t" .cpp); echo "build test: $name"; build_bin "$name" "$t"
done
for t in "${TOOLS[@]}"; do
    name=$(basename "$t" .cpp); echo "build tool: $name"; build_bin "$name" "$t"
done

# This script builds NO library. libwbcrypto.a is produced by the NDK
# cross-compile only (scripts/build_android.sh) — that is the sole shipping path,
# so there is no host copy to confuse with it and no .so link flags to get wrong.
# The benchmark is likewise Android-only: the O-MVLL plugin will not load into a
# host compiler (see EXTRA_CXXFLAGS above), so a host A/B would compare two
# unobfuscated builds. Use scripts/bench_android.sh.

# ---- run tests -------------------------------------------------------------
if [ "${1:-}" = "test" ]; then
    echo "=== running tests ==="
    rc=0
    for t in "${TESTS[@]}"; do name=$(basename "$t" .cpp); "$BUILD/$name" || rc=1; done
    exit $rc
fi
