#!/usr/bin/env bash
# collect_review_bundle.sh — package the SHIPPED artifacts for an external review
# (e.g. a fresh Opus analysis) and run a self-check so the hardening claims can be
# verified against the binary, not taken on trust.
#
# Usage:
#   NDK=$HOME/Library/Android/sdk/ndk/29.0.14206865 ./scripts/collect_review_bundle.sh [BUILD_DIR]
#
# BUILD_DIR defaults to ./build. Uses the NDK's llvm-* tools to inspect the
# aarch64 Android ELF (host readelf/nm won't be the right target). Output lands
# in ./review_bundle/ with a SELF-CHECK.txt evidence file.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD="${1:-build}"
OUT="review_bundle"
SO="$BUILD/libwbcrypto.so"

[ -f "$SO" ] || { echo "ERROR: $SO not found (build first)"; exit 1; }

# ---- locate llvm-* tools (prefer the NDK's, for the correct target) --------
LLVMBIN=""
if [ -n "${NDK:-}" ]; then
    for d in "$NDK"/toolchains/llvm/prebuilt/*/bin; do
        [ -d "$d" ] && LLVMBIN="$d" && break
    done
fi
_tool() {  # _tool <name> -> prints a usable path or empty
    local n="$1"
    if [ -n "$LLVMBIN" ] && [ -x "$LLVMBIN/llvm-$n" ]; then echo "$LLVMBIN/llvm-$n"
    elif command -v "llvm-$n" >/dev/null 2>&1; then echo "llvm-$n"
    elif command -v "$n" >/dev/null 2>&1; then echo "$n"; fi
}
READELF="$(_tool readelf)"; NM="$(_tool nm)"; STRINGS="$(_tool strings)"; OBJDUMP="$(_tool objdump)"

mkdir -p "$OUT"
cp "$SO" "$OUT/"
[ -f "$BUILD/libwbcrypto.a" ] && cp "$BUILD/libwbcrypto.a" "$OUT/"
cp include/wbcrypto.h "$OUT/"
# Include any sealed blob lying around as a seal-format sample (optional).
for b in *.blob "$BUILD"/*.blob; do [ -f "$b" ] && cp "$b" "$OUT/" && break; done

REPORT="$OUT/SELF-CHECK.txt"
{
    echo "=== libwbcrypto.so self-check (attach this to the review) ==="
    echo "generated: $(date)"
    echo "llvm tools: ${LLVMBIN:-<system PATH>}"
    echo
    echo "## file type / stripped?"
    command -v file >/dev/null 2>&1 && file "$SO"
    echo
    echo "## sections (expect NO .symtab, NO .debug_*)"
    [ -n "$READELF" ] && "$READELF" -S "$SO" | grep -Ei 'symtab|debug|comment' || echo "  (none found — good)"
    echo
    echo "## exported dynamic symbols (expect ONLY wbc_*)"
    if [ -n "$READELF" ]; then
        "$READELF" --dyn-syms "$SO" | awk '$4=="FUNC" && $7!="UND" {print $8}' | sort -u
    fi
    echo
    echo "## generator / reference-AES symbols anywhere in the .so (expect NONE)"
    if [ -n "$NM" ]; then
        "$NM" -D "$SO" 2>/dev/null | grep -Ei 'GenerateWhiteBox|AesEncrypt|KeyExpansion|AssembleWhiteBox|ExportTableImage' \
            || echo "  (none — generator not shipped, good)"
    fi
    echo
    echo "## sensitive strings (expect NONE: WBTS magic, source paths, table symbols)"
    if [ -n "$STRINGS" ]; then
        "$STRINGS" "$SO" | grep -Ei 'WBTS|aes_tables|trusted_storage|whitebox|src/|\.cpp' | sort -u \
            || echo "  (none — string encoding / strip effective, good)"
    fi
    echo
    echo "## control-flow-flattening smell test (indirect-branch density in .text)"
    if [ -n "$OBJDUMP" ]; then
        n=$("$OBJDUMP" -d "$SO" 2>/dev/null | grep -cE '\bbr\b|\bblr\b' || true)
        echo "  indirect branches (br/blr): $n  (higher => more flattening/indirection)"
    fi
} > "$REPORT" 2>&1

echo "bundle written to $OUT/:"
ls -la "$OUT"
echo
echo "---- SELF-CHECK.txt ----"
cat "$REPORT"
