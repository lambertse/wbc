# White-box Crypto VM — a virtualized trusted key store

A heavily-obfuscated **virtual machine** that acts as a container for
**white-box AES-128** and a **"trusted storage"** for the key. The AES key is
never present as bytes: it is diffused across a network of randomized lookup
tables (Chow's white-box construction), and that table-lookup program is
executed *inside* a custom bytecode VM whose interpreter and bytecode are
hardened with the obfuscation techniques from Tim Blazytko's
*Code Obfuscation and Deobfuscation Techniques* deck (`assets/tim-slide.pdf`).

```
 AES key ──▶ [white-box compiler] ──▶ table network (key diffused)
                                          │
                                          ▼
                         [assembler] ──▶ obfuscated VM bytecode
                                          │
                                          ▼
                         [trusted storage] ──▶ sealed blob on disk
                                          │
   plaintext block ─────────────────────▶ [VM: fetch-decode-execute] ──▶ ciphertext
```

**New here?** Read **[docs/OVERVIEW.md](docs/OVERVIEW.md)** for a
no-prerequisites explanation, then **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**
for the full component-by-component implementation. All docs:
[OVERVIEW](docs/OVERVIEW.md) · [ARCHITECTURE](docs/ARCHITECTURE.md) ·
[BUILD](docs/BUILD.md) · [ANTI-TAMPER](docs/ANTI-TAMPER.md).

## What it does

* **Phase 1 — the VM as a white-box container.** A generic register VM with a
  Harvard-style split between CODE, DATA and STACK memory, a fetch-decode-execute
  dispatcher over a handler table, **context-keyed firmware** (see below), opcode
  blinding (handler duplication), MBA-obfuscated index arithmetic, and opaque
  predicates with junk blocks. The compiled program is statically opaque
  (bytecode entropy ≈ 8 bits/byte).
* **Context-keyed firmware (`src/fw/`).** A *separate encryption toolchain*
  compiles the bytecode with a **feedback-evolving key** — no keystream is stored
  anywhere; the decode key derives from the firmware root, an interpreter
  fingerprint, and a checksum of each executed instruction. Consequences:
  patching **any** code byte, or re-mapping opcodes, cascades into garbage
  (runtime anti-tamper); and there is no single keystream to lift statically.
  (Honest ceiling: this hardens *static analysis and tampering*, not dynamic
  tracing — see [Threat model & honest limitations](#threat-model--honest-limitations).)
* **Phase 2 — trusted storage.** The compiled program is sealed at rest with a
  vetted AEAD: the table bank is encrypted with XChaCha20-Poly1305 under a key
  derived from the passphrase by Argon2id (memory-hard, random per-blob salt),
  and the whole program header (VM code, opcode maps, sizes) is authenticated as
  associated data. A wrong passphrase or any tamper fails authentication, so the
  blob does not open. Crypto is vendored libsodium (`third_party/fetch_deps.sh`),
  never home-rolled.

## Techniques from the deck → where they live

| Technique (slide)                              | Code |
|------------------------------------------------|------|
| Virtualization: VM entry, FDE dispatcher, handler table | `src/vm/vm.cpp`, `src/vm/handlers.cpp` |
| Made-up instruction set / encoded bytecode ("doesn't look like anything") | `src/vm/isa.h`, `src/vm/assembler.cpp` + context-keyed firmware `src/fw/` |
| Handler duplication / blinding (`handle_vadd'`, `handle_vadd''`) | `src/obf/blinding.*` |
| Mixed Boolean-Arithmetic (`mixed_boolean`)      | `src/obf/mba.h`, emitted in `src/vm/assembler.cpp` |
| Opaque predicates (true/false, dead code)       | `src/obf/opaque.h`, `EmitOpaqueGuard` in `src/vm/assembler.cpp` |
| White-box tables (T-box / Tyi / type-IV XOR; array select/store) | `src/wbaes/*` |

## White-box construction (Chow)

Built and tested in strata so any "encodings don't cancel" bug localizes to one
layer — each stratum must still compute plain AES:

1. **Naked** network — T-boxes (AddRoundKey+SubBytes) + Tyi (MixColumns) +
   type-IV nibble XOR tables, no encodings.
2. **Internal** — random 4-bit input/output encodings on every table; the
   encodings cancel between consecutive tables. **This is the level shipped.**

**External encodings are the identity**, so the white-box is a drop-in AES-128
and its output matches the FIPS-197 vector directly (the correctness anchor).
At runtime the white-box performs *only* table lookups and XORs — no GF(2⁸)
math — which is why the VM ISA is tiny.

## Build & run

> Detailed guides: **[docs/BUILD.md](docs/BUILD.md)** (build & CLI) and the C ABI
> header **[include/wbcrypto.h](include/wbcrypto.h)** (C library / FFI).
>
> The project builds three ways from one core: the **CLI tools**
> (`wb_keygen`/`wb_encrypt`), a **C-ABI SDK** (`libwbcrypto.a` / `libwbcrypto.so`
> + `include/wbcrypto.h`) for embedding in native projects, and the test suite.

No system cmake is required by the build script — it discovers a C++17 compiler
(`$CXX`/`$ZIG_BIN`, then system `c++`/`g++`/`clang++`). One dependency,
**libsodium** (the seal's KDF+AEAD), is vendored from source — `build.sh` fetches
it automatically (pinned + SHA256). If you only have a Zig toolchain, drive it via
`ZIG_BIN` (so `zig ar`/`zig cc` come along too):

```sh
./build.sh test                       # auto-fetches libsodium, builds, runs tests
ZIG_BIN=/path/to/zig ./build.sh test  # when only a Zig toolchain is available
./third_party/fetch_deps.sh           # (optional) vendor libsodium up front
```

A `CMakeLists.txt` is also provided for standard toolchains (mirrors the script;
`build.sh` is the tested path in this environment).

### CLI demo

```sh
# Seal an AES key into a trusted-storage blob (key is consumed, never stored):
./build/wb_keygen --key 000102030405060708090a0b0c0d0e0f --pass demo --out wb.blob

# Encrypt a block through the sealed, obfuscated VM:
./build/wb_encrypt --in wb.blob --pass demo --pt 00112233445566778899aabbccddeeff
# -> 69c4e0d86a7b0430d8cdb78070b4c55a   (== standard AES-128)
```

## Verification

`./build.sh test` runs:

* `test_aes_ref` — reference AES vs FIPS-197 known-answer + key expansion.
* `test_wbaes` — white-box == AES at each stratum, FIPS vector + random blocks,
  including a **random-key** dimension (exercises key expansion / final-round
  key folding beyond the fixed vector).
* `test_vm` — VM output differential-tested against the C++ white-box
  interpreter *and* the AES oracle, plain and fully-hardened bytecode, random
  keys.
* `test_obf` — every MBA identity over 200k random 32-bit pairs, opaque
  predicate over 100k inputs, opcode-blinding disjointness.
* `test_fw` — context-keyed firmware: decode == AES; **byte-tamper cascade**
  (flipping any code byte corrupts output); **interpreter binding** (re-mapping
  opcodes breaks decode); ≈ 8 bits/byte entropy, no stored keystream.
* `test_e2e` — seal→unseal→run == AES; **key absence** (neither key nor any
  round key appears in the blob or the decrypted tables); **AEAD auth**
  (flipping any blob byte or using a wrong passphrase fails to unseal); **salt
  uniqueness** (same key+passphrase sealed twice → different bytes, both open).

## Threat model & honest limitations

This is a faithful, working artifact — not an unbreakable key vault. The
layer-by-layer picture:

* **Chow's white-box AES is academically broken.** The BGE / Billet et al.
  attacks extract the key from the tables regardless of how clean the VM is
  (internal-encoding level; no 32-bit mixing bijections — see the deferred-work
  note below for why those were left out rather than added). The value is that the key
  is never a contiguous byte string and never materializes at runtime.
* **The VM + context-keyed firmware protect *static analysis and tampering*, not
  the key and not dynamic analysis.** Opcode blinding, MBA, opaque predicates and
  the feedback-evolving firmware make static disassembly hard and any patch
  self-destruct — but the program is straight-line, so anyone who *runs/traces*
  it recovers it, and the diffused key is unaffected.
* **Trusted-storage sealing protects the blob at rest, it is not key secrecy.**
  The seal uses Argon2id + XChaCha20-Poly1305 (authenticated), which resists
  offline passphrase guessing and tampering — but an attacker who runs the field
  binary has the passphrase, so durable protection needs hardware-backed device
  binding (`src/rt/device_binding.*`, roadmap).

Deferred / future work: 32-bit mixing bijections, dynamic-analysis hardening
(anti-debug, data-dependent control flow), space-hard constructions, and
hardware-backed device binding for the at-rest seal.
