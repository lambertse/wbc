#!/usr/bin/env bash
# build_android.sh — one command for the Android/ELF (arm64) build.
#
# This is a THIN WRAPPER around the CMake + NDK cross-compile, not a second build
# system. CMakeLists.txt stays the single source of truth.
#
# THIS SCRIPT IS THE ONLY WAY THE SHIPPED ARTIFACT IS BUILT. libwbcrypto.a exists
# for one purpose — to be linked into an Android .so — so it is produced here and
# nowhere else. scripts/build_host.sh is the host-side sibling and deliberately
# builds no library at all: only the tests and the two provisioning tools. If you
# find yourself wanting a host libwbcrypto.a, what you almost certainly want is
# scripts/gen_blob.sh (to seal a blob) or scripts/build_host.sh (to run the tests).
#
# Usage:
#   ./scripts/build_android.sh                    # obfuscated release .a + tools
#   ./scripts/build_android.sh --no-omvll         # same, obfuscation OFF
#   ./scripts/build_android.sh --target wb_bench  # one target only
#   ./scripts/build_android.sh --abi armeabi-v7a --api 21
#   ./scripts/build_android.sh --clean            # reconfigure from scratch
#
# Options:
#   --out DIR       build directory (default build-android; deliberately NOT
#                   `build`, which scripts/build_host.sh uses, so the two trees
#                   never clobber each other — see the libsodium cache note below)
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
        -h|--help)   sed -n '2,43p' "$0"; exit 0 ;;
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
        warn "DYLD_LIBRARY_PATH is unset — the plugin may fail to load (see docs/BUILD.md (O-MVLL section))"
    fi
else
    say "O-MVLL: DISABLED by --no-omvll"
fi

# Guard against the mistake this script exists to prevent: a host build tree and a
# cross build tree in the same directory. build_host.sh caches libsodium.a and skips
# rebuilding when the file is present, so a shared directory means the NEXT host
# build silently links an ELF archive (or vice versa) and fails with a wall of
# undefined symbols.
if [ "$OUT" = "build" ]; then
    warn "--out build collides with scripts/build_host.sh's default output directory.
      build_host.sh caches libsodium.a and will reuse this ELF one for a HOST build,
      failing with 'undefined symbol: sodium_memzero'. Prefer build-android."
fi
if [ "$OUT" = "build-host" ]; then
    warn "--out build-host collides with scripts/gen_blob.sh's output directory, whose
      libsodium.a cache is keyed to the HOST compiler. Prefer build-android."
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
NM=""; STRINGS=""
for d in "$NDK"/toolchains/llvm/prebuilt/*/bin; do
    [ -x "$d/llvm-nm" ] && NM="$d/llvm-nm"
    [ -x "$d/llvm-strings" ] && STRINGS="$d/llvm-strings"
done

# There is no .so to check any more — libwbcrypto.a is the one shipped artifact.
# Symbol hygiene moved WITH it: an archive has no dynamic symbol table to lock
# down, so `wbc_*` stays visible in it by design (that is how the consumer resolves
# it) and the hiding happens one link later, when the consumer links this archive
# into its own .so under -Wl,--exclude-libs,ALL or a version script. Verify it
# THERE, on the .so you actually ship; nothing this script can inspect will tell
# you whether that step worked.
#
# The archive is also the artifact that used to leak: 402 host paths, all in
# .debug_str/.debug_line, because nothing stripped it and the NDK toolchain puts -g
# on every compile line. -g0 + the POST_BUILD strip in CMakeLists.txt close that;
# the check below asserts they took effect. A leaked username and source layout is
# a ship-blocker, so it die()s rather than warn()s.
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

    # THE shipped-surface invariant: the runtime archive must define the runtime
    # ABI and must NOT define the provisioning surface. wbc_seal_key appearing here
    # means the CMake source split broke and every app linking this archive would
    # carry the white-box GENERATOR — the code that turns a raw AES key into a
    # table network. That is a ship-blocker, hence die().
    #
    # wbc_blob_kdf_tier is checked as the positive half: it is the 3.0.0-only
    # symbol the consumer's build greps for, so its absence means a stale archive.
    if [ -n "$NM" ]; then
        defined=$("$NM" --defined-only "$A" 2>/dev/null | awk '{print $NF}' | sort -u || true)
        case "$defined" in
            *wbc_seal_key*)
                die "$A defines wbc_seal_key — the runtime/provisioning split broke; do not ship this .a" ;;
        esac
        case "$defined" in
            *wbc_blob_kdf_tier*) say "shipped surface: OK (kdf_tier present, seal_key absent)" ;;
            *) die "$A does not define wbc_blob_kdf_tier — stale or wrong archive" ;;
        esac
    else
        warn "llvm-nm not found under \$NDK — skipping the shipped-surface check"
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

  # link $OUT/libwbcrypto.a into your own .so (hide the wbc_* names there with
  # -Wl,--exclude-libs,ALL or a version script), or run the on-device A/B:
  ./scripts/bench_android.sh                     # prints the blob's KDF tier up front
  ./scripts/bench_android.sh --kdf light --no-build

The host side is separate trees and separate commands:
  ./scripts/build_host.sh test   # the 7 correctness tests -> build/
  ./scripts/gen_blob.sh          # wb_keygen + wb_encrypt  -> build-host/
EOF
