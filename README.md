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

**New here?** Read on — this file is the overview. Then
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full
component-by-component implementation, and **[docs/BUILD.md](docs/BUILD.md)** for
how to build, seal a blob, and run the O-MVLL benchmark.

**Scope.** This SDK exists to serve one consumer:
[native-lib-encryption](https://github.com/lambertse/native-lib-encryption), which
encrypts Android `.so` files and needs a white-box to protect the long-term key.
The API is deliberately narrow to that contract — it wraps a *key* and ships no
bulk cipher of its own.

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
  derived from the passphrase and a random per-blob salt, and the whole program
  header (VM code, opcode maps, sizes) is authenticated as associated data. A
  wrong passphrase or any tamper fails authentication, so the blob does not open.
  The key derivation's cost is a **per-blob tier** — Argon2id (memory-hard) when
  a human chose the passphrase, HKDF when it is a high-entropy machine secret.
  That choice is the only thing standing between a ~2 ms and a ~250 ms
  `wbc_open`; see [`wbc_kdf_tier`](include/wbcrypto.h) and
  [ARCHITECTURE §6.1](docs/ARCHITECTURE.md). Crypto is vendored libsodium
  (`third_party/fetch_deps.sh`), never home-rolled.

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

> Detailed guide: **[docs/BUILD.md](docs/BUILD.md)**. The C ABI is documented in
> **[include/wbcrypto.h](include/wbcrypto.h)**.

**Two jobs, two machines.** Sealing a key is a *pack-host* operation; the runtime is
an *Android* artifact. Every script in `scripts/` is named for the one it does:

| Command | Produces |
|---|---|
| `./scripts/build_android.sh` | `build-android/libwbcrypto.a` — **the only artifact that ships** |
| `./scripts/gen_blob.sh` | `build-host/wb_keygen` + `wb_encrypt`, and a sealed `.blob` |
| `./scripts/build_host.sh test` | the 7 test suites |
| `./scripts/bench_android.sh` | the O-MVLL on/off A/B, on a device |

No host build produces a shipping library, and there is no shared library at all —
the consumer links `libwbcrypto.a` into its own `.so`.

The correctness build needs no cmake; it discovers a C++17 compiler
(`$ZIG_BIN`/`$CXX`, then system `c++`/`g++`/`clang++`). One dependency,
**libsodium** (the seal's KDFs + AEAD), is vendored from source and fetched
automatically (pinned + SHA256):

```sh
./scripts/build_host.sh test                       # auto-fetches libsodium, builds, runs tests
ZIG_BIN=/path/to/zig ./scripts/build_host.sh test  # when only a Zig toolchain is available
./third_party/fetch_deps.sh                        # (optional) vendor libsodium up front
```

`CMakeLists.txt` is the source of truth for the build graph;
`scripts/build_android.sh` wraps it with the NDK toolchain file.

### CLI demo

```sh
# Seal an AES key into a trusted-storage blob (key is consumed, never stored):
./build/wb_keygen --key 000102030405060708090a0b0c0d0e0f --pass demo --out wb.blob

# Encrypt a block through the sealed, obfuscated VM:
./build/wb_encrypt --in wb.blob --pass demo --pt 00112233445566778899aabbccddeeff
# -> 69c4e0d86a7b0430d8cdb78070b4c55a   (== standard AES-128)
```

## Verification

`./scripts/build_host.sh test` runs:

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

## Performance

`bench/wb_bench.cpp` measures the shipped runtime: the interpreter, block
encryption, key wrap/unwrap, blob open and its KDF. The interesting question is what
the O-MVLL native-code obfuscation costs, so `scripts/bench_android.sh` builds the
benchmark **twice from identical sources** — plugin on and off — and runs both on a
connected arm64 device, interleaved and CPU-pinned, then prints a per-surface ratio
table:

```sh
./scripts/bench_android.sh                     # on-device A/B — the real measurement
./scripts/bench_android.sh --kdf light --no-build
```

There is no host benchmark. The O-MVLL plugin is pinned to an NDK clang and will not
load into a host compiler, so a host A/B would compare two *unobfuscated* builds —
and the numbers that matter are a phone's anyway.

### One road: wrap a key, don't push data through the white-box

The white-box runs well under 1 MB/s because every 16-byte block is thousands of
obfuscated VM instructions. That slowness **is** the obfuscation — it cannot be
optimized away without deleting the protection. So the SDK deliberately offers **no
bulk entry point**, and no bulk cipher of its own: it protects a **key**, and you
move the **data** with a conventional cipher of your choosing.

```c
uint8_t sk[WBC_SESSION_KEY_BYTES], wrapped[WBC_WRAPPED_KEY_BYTES];
wbc_random(sk, sizeof sk);         /* fresh session key            */
wbc_wrap_key(ctx, sk, wrapped);    /* white-box wraps it, 2 blocks */
your_cipher_encrypt(sk, data, n);  /* ChaCha20 / AES-CTR / an AEAD */
wbc_wipe(sk, sizeof sk);           /* drop the plaintext key       */
```

Store `wrapped` next to the payload — it carries its own IV, generated inside
`wbc_wrap_key` so it cannot be reused. To read back: `wbc_unwrap_key`, then your
cipher. `sk` is 32 bytes, so it drops straight into ChaCha20, XChaCha20-Poly1305 or
AES-256 with no further derivation. The worked example is the ChaCha20 mirror in
[native-lib-encryption](https://github.com/lambertse/native-lib-encryption)'s
`stub/stub_cipher.h`, which decrypts a library's `.text` exactly this way.

**The white-box charge is fixed at two blocks per wrap** — it does not grow with the
payload, so the only term that scales is your own cipher. For reference, that
consumer reports ~13.7 ms total for a 5.5 MB `.text`: 1.1 ms open, 0.83 ms unwrap,
11.8 ms of its own ChaCha20 — against ~85 s if the payload itself went through the VM.

**The wrap is not separately authenticated**, and that is a contract you have to
honour. A corrupted `wrapped` still unwraps with `WBC_OK`; it just yields a
*different* session key. Detecting that is your cipher's job — an AEAD fails its tag,
a bare stream cipher gives you garbage you must be able to recognise. Never read
`WBC_OK` from `wbc_unwrap_key` as evidence that `wrapped` arrived intact.

**What this does and does not protect:** the white-box protects the long-term key —
that key is never reconstructed. It does **not** extend that guarantee to the session
key or the bulk data. Between the unwrap and the `wbc_wipe`, `sk` is an ordinary key
in ordinary memory, and an attacker who can dump the process gets it without touching
the white-box. That is a deliberate trade of coverage for throughput: keep the
plaintext session key's lifetime short and prefer a fresh key per message.

It refuses to report timings for a build whose ciphertext changed, and reports a
bound rather than a bogus number where a cost is smaller than the measurement noise.
See [docs/BUILD.md § Benchmarks](docs/BUILD.md#benchmarks--what-does-o-mvll-actually-cost).

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
  The seal uses XChaCha20-Poly1305 (authenticated) under a passphrase-derived
  key, which resists tampering and — at the Argon2id tiers — offline passphrase
  guessing. But an attacker who runs the field binary **has** the passphrase, so
  durable protection needs hardware-backed device binding — Android Keystore /
  StrongBox — which this SDK does **not** implement. A sketch of it used to sit in
  `src/rt/`, compiled into nothing and validated on no device; it was removed
  rather than left to read as a feature. Treat it as unaddressed.

  That last point is exactly why the KDF cost is a per-blob tier rather than a
  constant. When the passphrase ships inside the binary that opens the blob —
  the normal case for a packed shared library — there is nothing to guess, and
  paying Argon2id's ~250 ms buys no security at all. `WBC_KDF_NONE` is the
  honest choice there. It is *not* a general-purpose speedup: for a
  human-chosen passphrase it removes the one property the seal did have.

Deferred / future work: 32-bit mixing bijections, dynamic-analysis hardening
(anti-debug, data-dependent control flow), space-hard constructions, and
hardware-backed device binding for the at-rest seal.
