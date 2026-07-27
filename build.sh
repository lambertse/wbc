#!/usr/bin/env bash
# build.sh — compiler-discovering build for the white-box crypto VM.
#
# No system cmake/make is assumed. A C++17 compiler is discovered in this order:
#   1. $ZIG_BIN (path to a `zig` binary; drives both `zig c++` and `zig ar`)
#   2. $CXX if set
#   3. system c++ / g++ / clang++
#   4. a Zig toolchain: `zig` on PATH, or ./toolchain/zig-*/zig
# Usage:
#   ./build.sh            # build core, SDK libs, tools, tests, example
#   ./build.sh test       # the above, then run all tests
#   ZIG_BIN=/path/to/zig ./build.sh test
set -euo pipefail
cd "$(dirname "$0")"

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
if [ ${#ARCMD[@]} -eq 0 ]; then
    if command -v llvm-ar >/dev/null 2>&1; then ARCMD=(llvm-ar)
    elif command -v ar >/dev/null 2>&1; then ARCMD=(ar)
    elif command -v zig >/dev/null 2>&1; then ARCMD=(zig ar); fi
fi

# A plain C compiler for the C example (falls back to the C++ driver).
if [ -n "${ZIG_BIN:-}" ]; then CCCMD=("$ZIG_BIN" cc)
elif [ -n "${CC:-}" ]; then CCCMD=("$CC")
elif command -v cc >/dev/null 2>&1; then CCCMD=(cc)
else CCCMD=("${CXXCMD[@]}"); fi

BUILD=build
mkdir -p "$BUILD"
INCS=(-Isrc -Iinclude -Itests -Ifreestanding)
CXXFLAGS=(-std=c++17 -O2 "${INCS[@]}" -Wall -Wextra -Wno-nullability-completeness)

# Opt-in native-code obfuscation hook. Append extra compiler flags (e.g. an
# LLVM pass-plugin like O-MVLL: EXTRA_CXXFLAGS="-fpass-plugin=/path/OMVLL.so").
# Empty by default, so normal builds are unaffected. See docs/OBFUSCATION.md.
#   EXTRA_CXXFLAGS  — appended to every C++ compile
#   EXTRA_CFLAGS    — appended to the C example compile
#   EXTRA_LDFLAGS   — appended to every link (e.g. -Wl,-z,muldefs, which
#                     tolerates the duplicate EH-helper symbols O-MVLL can emit)
# Note: this is a HOST build. An LLVM pass-plugin requires a clang whose version
# matches the plugin (not AppleClang, not necessarily zig's clang). The fully
# tested O-MVLL path is the CMake + Android NDK cross-compile in docs/BUILD.md,
# not this script.
read -r -a EXTRA_CXX_ARR <<< "${EXTRA_CXXFLAGS:-}"
read -r -a EXTRA_C_ARR <<< "${EXTRA_CFLAGS:-}"
read -r -a EXTRA_LD_ARR <<< "${EXTRA_LDFLAGS:-}"
CXXFLAGS+=("${EXTRA_CXX_ARR[@]}")
[ -n "${EXTRA_CXXFLAGS:-}${EXTRA_CFLAGS:-}${EXTRA_LDFLAGS:-}" ] && echo "obfuscation flags: cxx='${EXTRA_CXXFLAGS:-}' c='${EXTRA_CFLAGS:-}' ld='${EXTRA_LDFLAGS:-}'"

CORE_SRCS=(
    src/wbaes/gf256.cpp src/wbaes/aes_ref.cpp src/wbaes/aes_tables.cpp
    src/wbaes/encodings.cpp src/wbaes/wb_generator.cpp src/wbaes/wb_interp.cpp
    src/wbaes/wb_export.cpp
    src/vm/assembler.cpp src/vm/vm.cpp src/vm/handlers.cpp
    src/fw/fwcrypt.cpp
    src/obf/blinding.cpp
    src/storage/trusted_storage.cpp
    src/sdk/wbcrypto.cpp
)
EXISTING=()
for s in "${CORE_SRCS[@]}"; do [ -f "$s" ] && EXISTING+=("$s"); done

echo "compiler: ${CXXCMD[*]}"
echo "archiver: ${ARCMD[*]:-<none>}"

build_bin() {  # build_bin <out> <main.cpp>
    local out="$1"; shift
    "${CXXCMD[@]}" "${CXXFLAGS[@]}" "$@" "${EXISTING[@]}" "${EXTRA_LD_ARR[@]}" -o "$BUILD/$out"
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

# ---- SDK static + shared libraries ----------------------------------------
if [ ${#ARCMD[@]} -ne 0 ]; then
    echo "build lib: libwbcrypto (static + shared)"
    OBJS=()
    for s in "${EXISTING[@]}"; do
        o="$BUILD/$(echo "$s" | tr '/.' '__').o"
        "${CXXCMD[@]}" "${CXXFLAGS[@]}" -fPIC -c "$s" -o "$o"
        OBJS+=("$o")
    done
    rm -f "$BUILD/libwbcrypto.a"
    "${ARCMD[@]}" rcs "$BUILD/libwbcrypto.a" "${OBJS[@]}"
    "${CXXCMD[@]}" -shared -fPIC "${OBJS[@]}" "${EXTRA_LD_ARR[@]}" -o "$BUILD/libwbcrypto.so"

    # C integration example, linked against the shared library.
    if [ -f examples/example.c ]; then
        echo "build example: example (C, links libwbcrypto.so)"
        "${CCCMD[@]}" -Iinclude "${EXTRA_C_ARR[@]}" examples/example.c \
            -L"$BUILD" -lwbcrypto "${EXTRA_LD_ARR[@]}" -Wl,-rpath,"$PWD/$BUILD" -o "$BUILD/example"
    fi
else
    echo "WARN: no archiver found; skipping static/shared library build" >&2
fi

# ---- freestanding device-runtime self-check --------------------------------
# The device stub runtime (freestanding/wb_stub.h) must compile with no libc and
# must not emit compiler-inserted libc calls (memcpy/memset/stack-protector).
if [ -f freestanding/selftest.c ]; then
    echo "check: freestanding runtime (-ffreestanding -nostdlib -fno-builtin)"
    "${CCCMD[@]}" -ffreestanding -fno-builtin -fno-stack-protector -nostdlib \
        -Ifreestanding -O2 -S freestanding/selftest.c -o "$BUILD/wb_stub.s"
    if grep -Eq 'memcpy|memset|memmove|__stack_chk' "$BUILD/wb_stub.s"; then
        echo "ERROR: freestanding runtime references libc:" >&2
        grep -E 'memcpy|memset|memmove|__stack_chk' "$BUILD/wb_stub.s" >&2
        exit 1
    fi
    "${CCCMD[@]}" -ffreestanding -fno-builtin -fno-stack-protector -nostdlib \
        -Ifreestanding -O2 -c freestanding/selftest.c -o "$BUILD/wb_stub.o"
fi

# ---- run tests -------------------------------------------------------------
if [ "${1:-}" = "test" ]; then
    echo "=== running tests ==="
    rc=0
    for t in "${TESTS[@]}"; do name=$(basename "$t" .cpp); "$BUILD/$name" || rc=1; done
    exit $rc
fi
