#!/usr/bin/env bash
# analyze_protection.sh — evidence-gathering harness for an INDEPENDENT review of
# the shipped white-box crypto runtime. Neutral by design: it collects facts and
# poses the attacker's questions; it does NOT assert pass/fail. The reviewing
# agent interprets the output adversarially (see the brief that accompanies it).
#
# Usage:
#   ./analyze_protection.sh <libwbcrypto.so> [sealed.blob]
#
# Optional: set NDK=/path/to/ndk to use its llvm-* tools (correct target for the
# aarch64 Android ELF). Otherwise system llvm-*/binutils are used if present.
set -uo pipefail   # NOT -e: we want every probe to run even if one tool is absent

SO="${1:-}"
BLOB="${2:-}"
[ -n "$SO" ] && [ -f "$SO" ] || { echo "usage: $0 <libwbcrypto.so> [sealed.blob]"; exit 2; }

# ---- locate tools ----------------------------------------------------------
LLVMBIN=""
if [ -n "${NDK:-}" ]; then
    for d in "$NDK"/toolchains/llvm/prebuilt/*/bin; do [ -d "$d" ] && LLVMBIN="$d" && break; done
fi
_tool(){ local n="$1"
    if [ -n "$LLVMBIN" ] && [ -x "$LLVMBIN/llvm-$n" ]; then echo "$LLVMBIN/llvm-$n"
    elif command -v "llvm-$n" >/dev/null 2>&1; then echo "llvm-$n"
    elif command -v "$n" >/dev/null 2>&1; then echo "$n"; fi; }
READELF="$(_tool readelf)"; NM="$(_tool nm)"; STRINGS="$(_tool strings)"; OBJDUMP="$(_tool objdump)"
SIZE="$(_tool size)"

rule(){ printf '\n============================================================\n%s\n============================================================\n' "$1"; }

rule "0. SUBJECT"
echo "file : $SO"
command -v file >/dev/null 2>&1 && file "$SO"
ls -l "$SO" | awk '{print "size :", $5, "bytes"}'
echo "tools: ${LLVMBIN:-<system PATH>}  (readelf=${READELF:-none} nm=${NM:-none} objdump=${OBJDUMP:-none} strings=${STRINGS:-none})"
echo "NOTE: this is an aarch64 Android ELF; use aarch64-aware tools. Running it"
echo "      dynamically needs an aarch64 device/emulator or qemu-aarch64."

rule "1. STATIC HYGIENE  (Q: how much does the binary hand the attacker for free?)"
if [ -n "$READELF" ]; then
    echo "-- sections (is there a .symtab / .debug_*? that would leak names & source):"
    "$READELF" -S "$SO" 2>/dev/null | awk '{print $2}' | grep -E '^\.' | tr '\n' ' '; echo
    echo
    echo "-- exported dynamic symbols (the labelled entry points an attacker sees):"
    "$READELF" --dyn-syms "$SO" 2>/dev/null | awk '$4=="FUNC" && $7!="UND"{print "   "$8}' | sort -u
    echo
    echo "-- count of exported vs imported dynamic symbols:"
    exp=$("$READELF" --dyn-syms "$SO" 2>/dev/null | awk '$7!="UND"&&$4=="FUNC"{c++}END{print c+0}')
    imp=$("$READELF" --dyn-syms "$SO" 2>/dev/null | awk '$7=="UND"{c++}END{print c+0}')
    echo "   exported FUNC: $exp   imported (UND): $imp"
fi
if [ -n "$NM" ]; then
    echo
    echo "-- key-generation / reference-cipher symbols present anywhere? (should an"
    echo "   attacker find the table generator or reference AES in the SHIPPED lib?):"
    "$NM" -D "$SO" 2>/dev/null | grep -Ei 'GenerateWhiteBox|AesEncrypt|KeyExpansion|Assemble|ExportTable|whitebox' \
        || echo "   (none found in dynamic symbols)"
fi

rule "2. STRING / CONSTANT LEAKAGE  (Q: does .rodata narrate the design?)"
if [ -n "$STRINGS" ]; then
    tot=$("$STRINGS" "$SO" | wc -l | tr -d ' ')
    echo "-- total extractable strings: $tot"
    echo "-- design-revealing hits (magic, source paths, subsystem names):"
    "$STRINGS" "$SO" | grep -Ein 'WBTS|whitebox|aes|argon2|chacha|poly1305|sodium|trusted_storage|\.cpp|src/|/Users/|table|sbox|s-box|seal|unseal' \
        | sort -u | head -60 || echo "   (no obvious design strings)"
    echo "   [interpret: libsodium's own strings (argon2/chacha) are expected; the"
    echo "    question is whether the PROJECT's magic/paths/table names appear.]"
fi

rule "3. OBFUSCATION EVIDENCE  (Q: is the native code actually hard to read?)"
if [ -n "$SIZE" ]; then echo "-- section sizes:"; "$SIZE" -A "$SO" 2>/dev/null | grep -E '\.text|\.rodata|\.data' ; fi
if [ -n "$OBJDUMP" ]; then
    echo
    echo "-- indirect-branch / indirect-call density (flattening & indirection raise these;"
    echo "   but a handler-table VM also has many by design — judge relative to size):"
    dis="$("$OBJDUMP" -d "$SO" 2>/dev/null)"
    printf '   %-22s %s\n' "indirect branch (br):"  "$(printf '%s' "$dis" | grep -cE '\bbr\b')"
    printf '   %-22s %s\n' "indirect call  (blr):"  "$(printf '%s' "$dis" | grep -cE '\bblr\b')"
    printf '   %-22s %s\n' "total insns (approx):"  "$(printf '%s' "$dis" | grep -cE '^\s+[0-9a-f]+:')"
    echo
    echo "   [attacker questions to answer from a disassembler (Ghidra/IDA/objdump):"
    echo "     - Do the seal/unseal & blob-loader functions show a flattening dispatcher"
    echo "       (one big switch on a state var)? If yes, static lifting is costly."
    echo "     - Is the VM dispatch loop readable? (it may be left light for perf.)"
    echo "     - Can you recover the opcode->handler map and dump clean bytecode"
    echo "       WITHOUT running the app?]"
fi

rule "4. SEAL / BLOB STRUCTURE  (Q: is the at-rest wrapper real crypto?)"
if [ -n "$BLOB" ] && [ -f "$BLOB" ]; then
    bs=$(ls -l "$BLOB" | awk '{print $5}')
    magic=$(dd if="$BLOB" bs=1 count=4 2>/dev/null)
    rdu32(){ od -An -tu4 -j "$1" -N4 "$BLOB" 2>/dev/null | tr -d ' '; }
    ver=$(rdu32 4); block_off=$(rdu32 48); code_len=$(rdu32 52); data_len=$(rdu32 56)
    echo "-- blob size: $bs bytes;  magic: '$magic'  version: $ver"
    echo "-- header fields: block_off=$block_off code_len=$code_len data_len=$data_len"
    echo "-- salt (16B @8, should be random per blob):"
    echo "     $(od -An -tx1 -j8  -N16 "$BLOB" 2>/dev/null | tr -s ' ')"
    echo "-- nonce (24B @24, should be random per blob):"
    echo "     $(od -An -tx1 -j24 -N24 "$BLOB" 2>/dev/null | tr -s ' ')"
    hdr=$((4+4+16+24+4+4+4+8+256+256))
    exp=$((hdr + code_len + data_len + 16))
    echo "-- layout check: header(580)+code($code_len)+ciphertext($data_len + 16 tag) = $exp vs actual $bs"
    if command -v python3 >/dev/null 2>&1; then
        echo "-- Shannon entropy of the ciphertext region (AEAD => ~8.0 bits/byte):"
        python3 - "$BLOB" $((hdr+code_len)) <<'PY'
import sys,math,collections
data=open(sys.argv[1],'rb').read()[int(sys.argv[2]):]
if data:
    c=collections.Counter(data); n=len(data)
    H=-sum(v/n*math.log2(v/n) for v in c.values())
    print(f"     {H:.3f} bits/byte over {n} bytes")
PY
    fi
    echo "   [attacker questions: same passphrase+key sealed twice -> different bytes?"
    echo "    (you only have ONE blob, so reason from salt/nonce presence + entropy)."
    echo "    Is there any KDF-less or keystream-reuse path? Is the header authenticated"
    echo "    (flip a header byte -> does wbc_open reject)? Test dynamically if possible.]"
else
    echo "(no blob supplied — skip; ask for a sealed .blob to assess the seal.)"
fi

rule "5. DYNAMIC PROBES  (optional; needs aarch64 device/emulator or qemu-aarch64)"
cat <<'EOF'
The white-box threat model GRANTS run/trace/instrument. If you can execute the
.so on aarch64, these are the decisive tests (build a tiny C driver against
wbcrypto.h that calls wbc_open + wbc_encrypt_block in a loop):

  a) Frida/QBDI-hook wbc_encrypt_block; dump memory around the context during a
     call and try to locate the ~1.5 MB table network; extract it.
  b) With the tables extracted, apply BGE (Billet-Gilbert-Ech-Chatbi) or the
     Lepoint-Rivain collision attack to recover the AES-128 key. Report the work
     factor you actually needed.
  c) Patch/NOP any integrity or environment check you find and see whether the
     cipher output stays CORRECT (a real binding makes patched code produce WRONG
     output; a bypassable branch does not).
  d) Trace one encryption: because the VM is data-oblivious, a single trace may
     reveal the whole program regardless of static obfuscation.
EOF

rule "DONE — hand this report to the reviewing agent with the accompanying brief."
