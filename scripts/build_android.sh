#!/usr/bin/env bash
# build_android.sh — one command for the Android/ELF (arm64) build.
#
# This is a THIN WRAPPER around the CMake + NDK cross-compile, not a second build
# system. CMakeLists.txt stays the single source of truth: it is the tested,
# shipped path, and it is the only one that gets the ELF symbol hygiene right
# (--version-script + --gc-sections + --strip-all, plus the llvm-strip post-step).
#
# Do NOT use ./build.sh for this. That script picks its .so link flags from
# `uname -s`, i.e. the HOST os — so cross-compiling ELF from macOS takes the
# Darwin branch, feeds Mach-O flags to an ELF linker, silently falls back to
# linking WITHOUT the hygiene flags, and produces a .so that exports vm::*,
# wbaes::* and storage::* instead of just wbc_*. See the check at the end of this
# script, which exists to catch exactly that class of mistake.
#
# Usage:
#   ./scripts/build_android.sh                    # obfuscated release .so + tools
#   ./scripts/build_android.sh --no-omvll         # same, obfuscation OFF
#   ./scripts/build_android.sh --target wb_bench  # one target only
#   ./scripts/build_android.sh --abi armeabi-v7a --api 21
#   ./scripts/build_android.sh --clean            # reconfigure from scratch
#
# Options:
#   --out DIR       build directory (default build-android; deliberately NOT
#                   `build`, so a host ./build.sh tree is never clobbered — see
#                   the note on the libsodium cache below)
#   --abi ABI       ANDROID_ABI (default arm64-v8a)
#   --api N         ANDROID_PLATFORM level (default 24)
#   --type T        CMAKE_BUILD_TYPE (default Release)
#   --target T      build just this target (repeatable); default: everything
#   --no-omvll      configure without the obfuscation pass-plugin
#   --clean         delete the build dir first
#   --jobs N        parallelism (default: all cores)
#
# ENVIRONMENT (required):
#   NDK             Android NDK root, e.g. ~/Library/Android/sdk/ndk/29.0.14206865
# ENVIRONMENT (required unless --no-omvll):
#   OMVLL_CONFIG        third_party/omvll/omvll_config.py  — WITHOUT it the plugin
#                       loads but applies NO passes, so you get an unobfuscated
#                       build that looks obfuscated. Defaulted below.
#   OMVLL_PYTHONPATH    third_party/python/Lib — the plugin embeds CPython 3.10.
#                       Defaulted below.
#   PYTHONHOME          only if your CPython is under pyenv, e.g.
#                       "$(pyenv root)/versions/3.10.7". Cannot be guessed.
#   DYLD_LIBRARY_PATH   macOS only; may be needed for the plugin to load.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

OUT="build-android"
ABI="arm64-v8a"
API=24
TYPE="Release"
USE_OMVLL=1
DO_CLEAN=0
JOBS=""
TARGETS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --out)       OUT="$2"; shift 2 ;;
        --abi)       ABI="$2"; shift 2 ;;
        --api)       API="$2"; shift 2 ;;
        --type)      TYPE="$2"; shift 2 ;;
        --target)    TARGETS+=("$2"); shift 2 ;;
        --no-omvll)  USE_OMVLL=0; shift ;;
        --clean)     DO_CLEAN=1; shift ;;
        --jobs)      JOBS="$2"; shift 2 ;;
        -h|--help)   sed -n '2,47p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- preflight --------------------------------------------------------------
# Everything that can be checked cheaply is checked here, because the failure
# modes further in are opaque: a missing OMVLL_PYTHONPATH aborts with "failed to
# get the Python codec of the filesystem encoding" thirty seconds into a compile.
say "preflight"

[ -n "${NDK:-}" ] || die "NDK is not set.
       export NDK=\$HOME/Library/Android/sdk/ndk/<version>     (macOS)
       export NDK=\$ANDROID_HOME/ndk/<version>                 (Linux)"
[ -d "$NDK" ] || die "NDK=$NDK does not exist"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
[ -f "$TOOLCHAIN" ] || die "no toolchain file at $TOOLCHAIN — is NDK=$NDK really an NDK root?"

command -v cmake >/dev/null 2>&1 || die "cmake not found"
command -v ninja >/dev/null 2>&1 || die "ninja not found (this path uses -GNinja)"

PLUGIN="$ROOT/third_party/omvll/omvll_ndk_r29.dylib"
if [ "$USE_OMVLL" -eq 1 ]; then
    # Fetched on demand, exactly as -DOMVLL=ON would do.
    if [ ! -f "$PLUGIN" ]; then
        say "fetching the O-MVLL plugin (not committed)"
        ./third_party/fetch_deps.sh omvll
    fi
    [ -f "$PLUGIN" ] || die "plugin still missing at $PLUGIN"

    # These two have sane in-repo defaults, so fill them in rather than nagging.
    if [ -z "${OMVLL_CONFIG:-}" ]; then
        export OMVLL_CONFIG="$ROOT/third_party/omvll/omvll_config.py"
        say "OMVLL_CONFIG defaulted to $OMVLL_CONFIG"
    fi
    if [ -z "${OMVLL_PYTHONPATH:-}" ]; then
        export OMVLL_PYTHONPATH="$ROOT/third_party/python/Lib"
        say "OMVLL_PYTHONPATH defaulted to $OMVLL_PYTHONPATH"
    fi
    [ -f "$OMVLL_CONFIG" ] || die "OMVLL_CONFIG=$OMVLL_CONFIG does not exist"
    [ -d "$OMVLL_PYTHONPATH" ] || die "OMVLL_PYTHONPATH=$OMVLL_PYTHONPATH is not a directory.
       Run ./third_party/fetch_deps.sh python"

    # PYTHONHOME cannot be guessed — it depends on how your CPython is installed.
    [ -n "${PYTHONHOME:-}" ] || warn "PYTHONHOME is unset. If your CPython is under pyenv the
      plugin will abort; export PYTHONHOME=\"\$(pyenv root)/versions/3.10.7\""
    if [ "$(uname -s)" = "Darwin" ] && [ -z "${DYLD_LIBRARY_PATH:-}" ]; then
        warn "DYLD_LIBRARY_PATH is unset — the plugin may fail to load (see docs/BUILD.md Option C)"
    fi
else
    say "O-MVLL: DISABLED by --no-omvll"
fi

# Guard against the mistake this script exists to prevent: a host build tree and
# a cross build tree in the same directory. build.sh caches libsodium.a and skips
# rebuilding when the file is present, so a shared directory means the NEXT host
# build silently links an ELF archive (or vice versa) and fails with a wall of
# undefined symbols.
if [ "$OUT" = "build" ]; then
    warn "--out build collides with ./build.sh's default output directory.
      build.sh caches libsodium.a and will reuse this ELF one for a HOST build,
      failing with 'undefined symbol: sodium_memzero'. Prefer build-android."
fi

[ "$DO_CLEAN" -eq 1 ] && { say "cleaning $OUT"; rm -rf "$OUT"; }

# ---- configure + build ------------------------------------------------------
CMAKE_ARGS=(
    -GNinja -B "$OUT" -S "$ROOT"
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN"
    -DANDROID_ABI="$ABI"
    -DANDROID_PLATFORM="android-$API"
    -DCMAKE_BUILD_TYPE="$TYPE"
)
[ "$USE_OMVLL" -eq 1 ] && CMAKE_ARGS+=(-DOMVLL_PLUGIN="$PLUGIN")

say "configuring: abi=$ABI api=$API type=$TYPE out=$OUT omvll=$USE_OMVLL"
cmake "${CMAKE_ARGS[@]}"

BUILD_ARGS=(--build "$OUT")
if [ -n "$JOBS" ]; then BUILD_ARGS+=(-j "$JOBS"); else BUILD_ARGS+=(-j); fi
if [ ${#TARGETS[@]} -gt 0 ]; then
    for t in "${TARGETS[@]}"; do BUILD_ARGS+=(--target "$t"); done
    say "building targets: ${TARGETS[*]}"
else
    say "building all targets"
fi
cmake "${BUILD_ARGS[@]}"

# ---- verify the artifact ----------------------------------------------------
# The point of this script is a correct ELF with the symbol table locked down, so
# assert both rather than trusting that the flags took effect. A .so that links
# but exports its internals is the specific regression the CMake path guards
# against and build.sh silently does not.
SO="$OUT/libwbcrypto.so"
NM=""; READELF=""; STRINGS=""
for d in "$NDK"/toolchains/llvm/prebuilt/*/bin; do
    [ -x "$d/llvm-readelf" ] && READELF="$d/llvm-readelf"
    [ -x "$d/llvm-nm" ] && NM="$d/llvm-nm"
    [ -x "$d/llvm-strings" ] && STRINGS="$d/llvm-strings"
done

if [ -f "$SO" ]; then
    say "artifact: $SO ($(wc -c < "$SO" | tr -d ' ') bytes)"

    if [ -n "$READELF" ]; then
        # Format: must be ELF, and the right machine for the requested ABI.
        hdr=$("$READELF" -h "$SO" 2>/dev/null || true)
        case "$hdr" in
            *ELF*) ;;
            *) die "$SO is not an ELF object — the toolchain file did not take effect" ;;
        esac
        mach=$(printf '%s\n' "$hdr" | sed -n 's/^ *Machine: *//p')
        say "format: ELF, machine=${mach:-unknown}"

        # Symbol hygiene: the dynamic symbol table must EXPORT only wbc_*.
        #
        # Two filters matter here and both were found by testing rather than
        # reasoning. Columns are: Num Value Size Type Bind(5) Vis Ndx(7) Name(8).
        #   * Ndx == UND means the symbol is IMPORTED, not exported — every real
        #     .so imports __cxa_finalize, memcpy and friends. Counting those as
        #     leaks makes the check fire on every correct build, which trains you
        #     to ignore it.
        #   * WEAK is as exported as GLOBAL, so check both binds.
        leaked=$("$READELF" --dyn-syms "$SO" 2>/dev/null \
                 | awk '$8 != "" && ($5 == "GLOBAL" || $5 == "WEAK") && $7 != "UND" {print $8}' \
                 | grep -v '^wbc_' | grep -v '^$' | sort -u || true)
        if [ -n "$leaked" ]; then
            warn "libwbcrypto.so exports symbols other than wbc_*:"
            printf '%s\n' "$leaked" | sed 's/^/        /' >&2
            warn "the --version-script did not apply; do not ship this .so"
        else
            say "symbol hygiene: OK (exports only wbc_*)"
        fi
    else
        warn "llvm-readelf not found under \$NDK — skipping the format/symbol checks"
    fi
else
    say "no $SO (expected if --target selected something else)"
fi

# The static archive ships too (docs/BUILD.md), and it is the artifact that used
# to leak: 402 host paths, all in .debug_str/.debug_line, because nothing stripped
# it and the NDK toolchain puts -g on every compile line. -g0 + the POST_BUILD
# strip in CMakeLists.txt close that; this asserts they took effect, in the same
# spirit as the symbol check above. A leaked username and source layout is a
# ship-blocker, so this die()s rather than warn()s.
A="$OUT/libwbcrypto.a"
if [ -f "$A" ]; then
    say "artifact: $A ($(wc -c < "$A" | tr -d ' ') bytes)"
    if [ -n "$STRINGS" ]; then
        # Look for this machine's paths, not just a hardcoded /Users — $ROOT is
        # what the prefix map is supposed to have rewritten to './'.
        paths=$("$STRINGS" "$A" 2>/dev/null \
                | grep -E "(^|[^a-zA-Z0-9_])(${ROOT}|${HOME}|/Users/|/home/)" \
                | sort -u | head -20 || true)
        if [ -n "$paths" ]; then
            printf '%s\n' "$paths" | sed 's/^/        /' >&2
            die "$A embeds host paths — -g0/-ffile-prefix-map did not take effect; do not ship this .a"
        fi
        say "path hygiene: OK (no host paths in $(basename "$A"))"

        # Release only: Debug/RelWithDebInfo keep DWARF on purpose, and there the
        # path check above is the whole point. This is the positive signal that
        # -g0 took effect — a grep that passes on a stale or partially rebuilt
        # tree is the false pass to guard against. DWARF was 46% of this archive,
        # so the byte count printed above moves visibly when it is gone.
        if [ "$TYPE" = "Release" ]; then
            if "$STRINGS" "$A" 2>/dev/null | grep -q '\.debug_info'; then
                warn "$A still contains DWARF sections — -g0 did not take effect"
            else
                say "debug info: OK (no DWARF sections)"
            fi
        else
            say "debug info: DWARF kept (type=$TYPE); paths checked above"
        fi
    else
        warn "llvm-strings not found under \$NDK — skipping the archive path/DWARF checks"
    fi
else
    say "no $A (expected if --target selected something else)"
fi

cat <<EOF

==> done. Next steps:

  # provision a blob on the HOST (never on device — see docs/BUILD.md).
  # --kdf picks what every wbc_open of that blob will cost; it is recorded in the
  # blob, NOT in this build, so the .so you just built opens any tier.
  ./scripts/gen_blob.sh                          # --kdf heavy (default), open ~250 ms
  ./scripts/gen_blob.sh --kdf light --pass "\$(openssl rand -hex 16)"
                                                 # open ~2 ms; needs a RANDOM pass
                                                 # (see wbc_kdf_tier in wbcrypto.h)

  # push the .so into your app, or run the on-device A/B:
  ./scripts/bench_android.sh                     # prints the blob's KDF tier up front
  ./scripts/bench_android.sh --kdf light --no-build

Host build is a separate tree and a separate command:
  ./build.sh                 # Mach-O/native -> build/
EOF
