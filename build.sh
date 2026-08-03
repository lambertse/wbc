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
#   OPT_LEVEL=-O3 ./build.sh
# and use scripts/bench_host_ab.sh to compare, rather than eyeballing two runs.
OPT_LEVEL="${OPT_LEVEL:--O2}"
INCS=(-Isrc -Iinclude -Itests "-I$SODIUM_INC")
CXXFLAGS=(-std=c++17 "$OPT_LEVEL" "${INCS[@]}" -Wall -Wextra -Wno-nullability-completeness
          -fvisibility=hidden -fvisibility-inlines-hidden
          -ffunction-sections -fdata-sections)

# Opt-in native-code obfuscation hook. Append extra compiler flags (e.g. an
# LLVM pass-plugin like O-MVLL: EXTRA_CXXFLAGS="-fpass-plugin=/path/OMVLL.so").
# Empty by default, so normal builds are unaffected. See docs/BUILD.md.
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
[ -n "${EXTRA_CXXFLAGS:-}${EXTRA_CFLAGS:-}${EXTRA_LDFLAGS:-}" ] && echo "obfuscation flags: cxx='${EXTRA_CXXFLAGS:-}' c='${EXTRA_CFLAGS:-}' ld='${EXTRA_LDFLAGS:-}'"

# RUNTIME set: ships in libwbcrypto.{a,so}. Field-side only — open a sealed blob
# and encrypt. Deliberately excludes the reference AES, the white-box generator,
# and the bytecode assembler.
RUNTIME_SRCS=(
    src/vm/vm.cpp src/vm/handlers.cpp
    src/storage/trusted_storage.cpp
    src/sdk/wbcrypto.cpp
)
# PROVISIONING set: key-generation surface. Linked only into the provisioning
# tools / libwbprovision.a; MUST NOT ship in the runtime library.
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
        "${CCCMD[@]}" -O2 -fPIC -fvisibility=hidden -DCONFIGURED=1 \
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

# Benchmark — a HOST (unobfuscated) baseline you can run immediately:
#   ./scripts/gen_blob.sh && ./build/wb_bench --blob sealed.blob --pass demo
# The O-MVLL on/off comparison is an arm64 Android device run; see
# scripts/bench_android.sh and docs/BUILD.md ("Benchmarks").
# NOTE: `./build.sh test` iterates only TESTS, so it does NOT run wb_bench. That
# is intentional — a benchmark asserts nothing and would only slow the suite down.
if [ -f bench/wb_bench.cpp ]; then
    echo "build bench: wb_bench"; build_bin wb_bench -Ibench bench/wb_bench.cpp
fi
# Attribution ladder: plain AES vs the table network vs the VM. Needs the
# PROVISIONING set (it generates its own white-box), which build_bin links
# anyway; under CMake it gets its own target for the same reason.
if [ -f bench/wb_ladder.cpp ]; then
    echo "build bench: wb_ladder"; build_bin wb_ladder -Ibench bench/wb_ladder.cpp
fi

# ---- SDK libraries ---------------------------------------------------------
# libwbcrypto.{a,so} : shipped RUNTIME library (runtime objs + libsodium).
# libwbprovision.a   : host-only PROVISIONING library (adds the keygen surface).
# The .so exports ONLY wbc_* (version script + -fvisibility=hidden) and is
# stripped, so it ships neither a labelled symbol map nor DWARF.
compile_objs() {  # compile_objs <suffix> <src...> ; echoes object paths
    local suffix="$1"; shift
    local objs=()
    for s in "$@"; do
        local o="$BUILD/${suffix}_$(echo "$s" | tr '/.' '__').o"
        "${CXXCMD[@]}" "${CXXFLAGS[@]}" -fPIC -c "$s" -o "$o"
        objs+=("$o")
    done
    printf '%s\n' "${objs[@]}"
}

if [ ${#ARCMD[@]} -ne 0 ]; then
    echo "build lib: libwbcrypto (runtime static + shared)"
    # `mapfile`/`readarray` is bash 4.0+; use a portable read loop (bash 3.2 too).
    RT_OBJS=();     while IFS= read -r __o; do RT_OBJS+=("$__o");     done < <(compile_objs rt "${RUNTIME[@]}")
    PV_OBJS=();     while IFS= read -r __o; do PV_OBJS+=("$__o");     done < <(compile_objs pv "${PROVISION[@]}")
    SODIUM_OBJS=(); while IFS= read -r __o; do SODIUM_OBJS+=("$__o"); done < <(find "$BUILD/sodium" -name '*.o' | sort)

    # Symbol-hygiene link flags. The GNU set below is ELF-only: Apple's ld64
    # rejects it outright with
    #   ld: unknown options: --gc-sections --build-id=none --strip-all --version-script=...
    # so macOS needs the Mach-O equivalents. Same intent either way — export only
    # wbc_*, drop dead code, keep internal symbols out of the table.
    VERSCRIPT="src/sdk/wbcrypto.map"
    case "$(uname -s)" in
        Darwin)
            # ld64 has no version scripts; -exported_symbol takes globs, and C
            # symbols carry a leading underscore in Mach-O. -x strips local symbols
            # (there is no --strip-all), -dead_strip is --gc-sections.
            SO_LDFLAGS=(-Wl,-dead_strip -Wl,-x "-Wl,-exported_symbol,_wbc_*")
            ;;
        *)
            SO_LDFLAGS=(-Wl,--gc-sections -Wl,--build-id=none -Wl,--strip-all)
            [ -f "$VERSCRIPT" ] && SO_LDFLAGS+=("-Wl,--version-script=$VERSCRIPT")
            ;;
    esac

    # Runtime shared library: runtime objs + only the libsodium objects actually
    # referenced (archive members are pulled in on demand).
    # If the hygiene flags are not understood by this linker, retry without them:
    # a host build that links is worth more than one that enforces symbol hiding,
    # and the SHIPPED artifact is the CMake/NDK build, which is unaffected.
    if ! "${CXXCMD[@]}" -shared -fPIC "${RT_OBJS[@]}" "$SODIUM_A" \
            "${SO_LDFLAGS[@]}" ${EXTRA_LD_ARR[@]+"${EXTRA_LD_ARR[@]}"} \
            -o "$BUILD/libwbcrypto.so" 2>/dev/null; then
        echo "WARN: linker rejected the symbol-hygiene flags (${SO_LDFLAGS[*]});" >&2
        echo "      relinking libwbcrypto.so without them — it will export more than wbc_*." >&2
        "${CXXCMD[@]}" -shared -fPIC "${RT_OBJS[@]}" "$SODIUM_A" \
            ${EXTRA_LD_ARR[@]+"${EXTRA_LD_ARR[@]}"} -o "$BUILD/libwbcrypto.so"
    fi

    # Self-contained static archives (bundle the libsodium objects).
    rm -f "$BUILD/libwbcrypto.a" "$BUILD/libwbprovision.a"
    "${ARCMD[@]}" rcs "$BUILD/libwbcrypto.a" "${RT_OBJS[@]}" "${SODIUM_OBJS[@]}"
    "${ARCMD[@]}" rcs "$BUILD/libwbprovision.a" \
        "${RT_OBJS[@]}" "${PV_OBJS[@]}" "${SODIUM_OBJS[@]}"

    # C integration examples. They demonstrate the FULL lifecycle (seal offline +
    # run), so they link the host PROVISIONING archive (libwbprovision.a, which
    # also contains the runtime). A real field app links only libwbcrypto.so and
    # never calls wbc_seal_key.
    #
    # Driven by the C++ compiler so libc++ resolves at link, but `-x c` forces
    # the SOURCE to be compiled as C. Without it the driver compiles .c as C++
    # ("treating 'c' input as 'c++' ... deprecated") and these files then have to
    # satisfy C++ rules they were never written for — e.g. no implicit void*
    # conversion, so a plain malloc() is a hard error. `-x none` afterwards puts
    # the driver back to by-extension handling for the archive.
    for ex in examples/*.c; do
        [ -f "$ex" ] || continue
        exname=$(basename "$ex" .c)
        echo "build example: $exname (C, links libwbprovision.a)"
        "${CXXCMD[@]}" -Iinclude ${EXTRA_C_ARR[@]+"${EXTRA_C_ARR[@]}"} \
            -x c "$ex" -x none \
            "$BUILD/libwbprovision.a" ${EXTRA_LD_ARR[@]+"${EXTRA_LD_ARR[@]}"} -o "$BUILD/$exname"
    done
else
    echo "WARN: no archiver found; skipping static/shared library build" >&2
fi

# ---- run tests -------------------------------------------------------------
if [ "${1:-}" = "test" ]; then
    echo "=== running tests ==="
    rc=0
    for t in "${TESTS[@]}"; do name=$(basename "$t" .cpp); "$BUILD/$name" || rc=1; done
    exit $rc
fi
