#!/usr/bin/env bash
# gen_blob.sh — build a NATIVE (host) wb_keygen and seal a key into a .blob, in
# one command, fully isolated from the shipped Android/O-MVLL build.
#
# Why this exists: the obfuscated cross-compiled build (CMake+NDK, or build.sh
# with EXTRA_CXXFLAGS) produces an aarch64 wb_keygen that CANNOT run on your
# host, and blob provisioning must never be obfuscated. This script therefore:
#   * uses its own build dir (build-host/), so ./build (the Android artifacts) is
#     never clobbered;
#   * deliberately IGNORES EXTRA_CXXFLAGS / EXTRA_LDFLAGS / ZIG_BIN so no O-MVLL
#     plugin or cross toolchain leaks in;
#   * caches libsodium in build-host/, so re-runs are instant.
#
# Usage:
#   ./scripts/gen_blob.sh                                   # demo key -> sealed.blob
#   ./scripts/gen_blob.sh --key <32hex> --pass P --seed N --out out.blob
#   HOST_CXX=/path/to/clang++ ./scripts/gen_blob.sh ...     # force a compiler
# Any args are passed straight through to wb_keygen.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD="build-host"
SODIUM_ROOT="third_party/libsodium/libsodium-1.0.20"
SODIUM_INC="$SODIUM_ROOT/src/libsodium/include"
[ -f "$SODIUM_INC/sodium.h" ] || ./third_party/fetch_deps.sh libsodium
[ -f "$SODIUM_INC/sodium.h" ] || { echo "libsodium still missing — run ./third_party/fetch_deps.sh libsodium" >&2; exit 1; }

# --- native host compiler (never ZIG_BIN, never EXTRA_CXXFLAGS) --------------
# On macOS prefer the SYSTEM toolchain explicitly (/usr/bin/clang++ + /usr/bin/ar)
# over whatever `c++`/`ar` resolve to on PATH. A Homebrew clang/binutils earlier on
# PATH pairs a newer compiler with Apple's system `ld`, and the mismatch surfaces
# only later, as an opaque archive/link error such as
#   ld: archive member invalid control bits in 'build-host/libsodium.a'
# Provisioning is host-only glue, so there is no reason to prefer a newer compiler
# here. Override with HOST_CXX / HOST_AR if you really want a different one.
CXX="${HOST_CXX:-}"
if [ -z "$CXX" ]; then
    if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/clang++ ]; then
        CXX=/usr/bin/clang++
    else
        for c in c++ clang++ g++; do command -v "$c" >/dev/null 2>&1 && CXX="$c" && break; done
    fi
fi
[ -n "$CXX" ] || { echo "no host C++ compiler found (set HOST_CXX)" >&2; exit 1; }
AR="${HOST_AR:-}"
if [ -z "$AR" ]; then
    # Same reasoning as CXX above: pair Apple's ar with Apple's ld.
    if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/ar ]; then
        AR=/usr/bin/ar
    else
        for a in ar llvm-ar; do command -v "$a" >/dev/null 2>&1 && AR="$a" && break; done
    fi
fi
[ -n "$AR" ] || { echo "no archiver found (set HOST_AR)" >&2; exit 1; }
echo "host compiler: $CXX    archiver: $AR"

INCS=(-Isrc -Iinclude "-I$SODIUM_INC")
CXXFLAGS=(-std=c++17 -O2 "${INCS[@]}" -w)   # -w: this is a provisioning tool, not the shipped code

mkdir -p "$BUILD"

# --- libsodium (cached, keyed to compiler+platform) --------------------------
# The cache is stamped with the toolchain + `uname` so a build-host/ populated by
# a DIFFERENT target (e.g. a Linux/cross build in a shared tree) is not reused —
# that mismatch is what produces "archive member '/' not a mach-o file".
SODIUM_A="$BUILD/libsodium.a"
STAMP="$BUILD/.sodium-cc"
WANT="$CXX|$AR|$(uname -sm)"
if [ ! -f "$SODIUM_A" ] || [ "$(cat "$STAMP" 2>/dev/null || true)" != "$WANT" ]; then
    echo "building libsodium (host, one-time)..."
    rm -rf "$BUILD/sodium" "$SODIUM_A" "$STAMP"
    mkdir -p "$BUILD/sodium"
    sobjs=()
    while IFS= read -r c; do
        o="$BUILD/sodium/$(echo "$c" | tr '/.' '__').o"
        "$CXX" -x c -O2 -DCONFIGURED=1 -I"$SODIUM_INC" -I"$SODIUM_INC/sodium" -c "$c" -o "$o"
        sobjs+=("$o")
    done < <(find "$SODIUM_ROOT/src/libsodium" -name '*.c' | sort)
    "$AR" rcs "$SODIUM_A" "${sobjs[@]}"
    # On macOS, sanity-check the archive FORMAT now rather than letting a bad one
    # surface two steps later as an opaque linker error. Read the first member's
    # 16-byte name field (at offset 8, right after the "!<arch>\n" magic): a
    # BSD/Mach-O archive names its symbol table "__.SYMDEF" (or "__.SYMDEF SORTED"),
    # a GNU one just "/". Apple's ld only understands the former, so a GNU/LLVM ar
    # sneaking onto PATH is caught here instead of at link time. But see the
    # extended-name note below before touching the comparison.
    # Scope note: this catches the wrong-archive-FORMAT case only. It does not catch
    # a format-valid archive whose member objects the system ld still dislikes —
    # that is what preferring /usr/bin/clang++ above is for.
    # NOTE: do NOT try to detect this with `ar t` — ar omits the special members
    # from its listing, so such a check silently never fires.
    # IMPORTANT: the 16-byte name field is often NOT the literal name. BSD/Mach-O
    # stores any name that is long or contains a space OUT OF LINE: the field
    # reads "#1/<len>" and the real name occupies the first <len> bytes of the
    # member data (offset 68 = 8 magic + 60 header). Apple's own ar does this for
    # the symbol table — "#1/12" for "__.SYMDEF", "#1/20" for "__.SYMDEF SORTED"
    # — so matching only a literal "__.SYMDEF" rejects the very archives this
    # check exists to bless. Resolve the extended form before judging.
    if [ "$(uname -s)" = "Darwin" ]; then
        first_member=$(dd if="$SODIUM_A" bs=1 skip=8 count=16 2>/dev/null || true)
        case "$first_member" in
            '#1/'*)
                ext_len=$(printf '%s' "${first_member#\#1/}" | tr -dc '0-9')
                # Trailing NULs pad the name to the alignment; strip them.
                first_member=$(dd if="$SODIUM_A" bs=1 skip=68 count="${ext_len:-0}" \
                                  2>/dev/null | tr -d '\0' || true) ;;
        esac
        case "$first_member" in
            __.SYMDEF*) ;;  # BSD/Mach-O — good (GNU names its table "/")
            *)
                echo "ERROR: '$AR' produced a non-Mach-O archive ($SODIUM_A):" >&2
                echo "       symbol-table member is '${first_member}', expected '__.SYMDEF'." >&2
                echo "       Apple's ld cannot read it ('archive member invalid control" >&2
                echo "       bits'). A GNU/LLVM ar is probably shadowing Apple's on PATH." >&2
                echo "       '$AR' is what was used; check 'which -a ar' and force a" >&2
                echo "       different one with HOST_AR=/path/to/ar $0 $*" >&2
                rm -f "$SODIUM_A" "$STAMP"
                exit 1 ;;
        esac
    fi
    printf '%s' "$WANT" > "$STAMP"
fi

# --- host wb_keygen + wb_encrypt (full lib source set, minus tool/rt mains) ---
SRCS=()
while IFS= read -r f; do SRCS+=("$f"); done \
    < <(find src -name '*.cpp' -not -path 'src/tools/*' -not -path 'src/rt/*' | sort)

echo "building host wb_keygen + wb_encrypt..."
"$CXX" "${CXXFLAGS[@]}" src/tools/wb_keygen.cpp  "${SRCS[@]}" "$SODIUM_A" -o "$BUILD/wb_keygen"
"$CXX" "${CXXFLAGS[@]}" src/tools/wb_encrypt.cpp "${SRCS[@]}" "$SODIUM_A" -o "$BUILD/wb_encrypt"

# --- seal (demo defaults if no args) -----------------------------------------
if [ "$#" -eq 0 ]; then
    set -- --key 000102030405060708090a0b0c0d0e0f --pass demo --seed 42 --out sealed.blob
    echo "no args given -> demo: $*"
fi
echo "--- wb_keygen $* ---"
"$BUILD/wb_keygen" "$@"

# --- optional self-check: if we sealed to --out with a --pass, verify it opens
out=""; pass=""; prev=""
for a in "$@"; do
    case "$prev" in --out) out="$a";; --pass) pass="$a";; esac; prev="$a"
done
if [ -n "$out" ] && [ -f "$out" ]; then
    echo "--- self-check: encrypt FIPS vector through $out ---"
    "$BUILD/wb_encrypt" --in "$out" ${pass:+--pass "$pass"} \
        --pt 00112233445566778899aabbccddeeff
    echo "(the demo key 000102..0f yields 69c4e0d86a7b0430d8cdb78070b4c55a)"
fi
