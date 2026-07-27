# Architecture & Implementation

A complete tour of how the White-box Crypto VM is built, component by component.
Read [OVERVIEW.md](OVERVIEW.md) first for the concepts and the honest security
framing. This document assumes you're comfortable reading C++ and want to know
*exactly* how each piece works and where it lives.

- [1. Component map](#1-component-map)
- [2. The pipeline at a glance](#2-the-pipeline-at-a-glance)
- [3. Layer 1 — White-box AES (Chow)](#3-layer-1--white-box-aes-chow)
- [4. Layer 2 — The virtual machine](#4-layer-2--the-virtual-machine)
- [5. Layer 3 — Context-keyed firmware](#5-layer-3--context-keyed-firmware)
- [6. Layer 4 — Trusted storage](#6-layer-4--trusted-storage)
- [7. Layer 5 — The C-ABI SDK](#7-layer-5--the-c-abi-sdk)
- [8. Layer 6 — Freestanding device runtime](#8-layer-6--freestanding-device-runtime)
- [9. End-to-end data flow](#9-end-to-end-data-flow)
- [10. Key data structures](#10-key-data-structures)
- [11. Sizes and numbers](#11-sizes-and-numbers)
- [12. Verification strategy](#12-verification-strategy)
- [13. Design decisions & rationale](#13-design-decisions--rationale)

---

## 1. Component map

~2,350 lines of dependency-free C++17 (plus one freestanding C header). Each
directory is one responsibility:

| Path | Responsibility |
|------|----------------|
| `src/wbaes/` | The **white-box compiler**: reference AES oracle, GF(2⁸) math, the Chow table network, encodings, and a plain interpreter of the tables. Consumes a key; emits a table network. |
| `src/vm/` | The **virtual machine**: instruction set, the compiler from tables → bytecode (assembler), the fetch-decode-execute interpreter, and the opcode handlers. |
| `src/fw/` | The **firmware toolchain**: the context-keyed decode schedule (shared math) and the encryptor that turns plaintext bytecode into a tamper-chained, keystream-free image. |
| `src/obf/` | **Obfuscation primitives**: MBA identities, opaque-predicate primitive, opcode blinding (handler duplication). Used by the assembler. |
| `src/storage/` | **Trusted storage**: serialize + seal a program into an at-rest blob with integrity binding. |
| `src/sdk/` | The **C ABI** (`libwbcrypto`): a thin, exception-safe wrapper over the C++ core. |
| `src/tools/` | The CLIs `wb_keygen` and `wb_encrypt`. |
| `freestanding/` | The **no-libc device runtime** (`wb_stub.h`) + the shared table-image layout + a compile-only self-check. |
| `include/wbcrypto.h` | The public SDK header. |
| `tests/` | Eight test suites (correctness, differential, tamper, freestanding). |

---

## 2. The pipeline at a glance

```
 key ─┬─► GenerateWhiteBox ──► WhiteBox (tables)
      │      src/wbaes/                │
      │                                ├─► AssembleWhiteBox ──► (plaintext bytecode + data image)
      │                                │      src/vm/                     │
      │                                │                                  ├─► EncryptFirmware ──► vm::Program
      │                                │                                  │      src/fw/
      │                                │                                  │
      │                                │                                  └─► Seal ──► sealed blob (bytes)
      │                                │                                         src/storage/
      │                                └─► ExportTableImage ──► flat table image (freestanding)
      │                                       src/wbaes/wb_export
      │
      └─► (reference AES oracle, src/wbaes/aes_ref, only used by tests)

 runtime:  Unseal ──► vm::Program ──► vm::Run ──► ciphertext
                                       src/vm/
```

Two distinct execution targets share the same tables:
- the **VM path** (host / SDK / CLI) runs the encrypted bytecode in the interpreter;
- the **freestanding path** (device stub) runs the exported tables directly.

---

## 3. Layer 1 — White-box AES (Chow)

**Goal:** turn one AES-128 key into a network of lookup tables that computes
standard AES-128 while the key never appears as bytes.

### 3.1 Foundations

- `src/wbaes/gf256.{h,cpp}` — arithmetic in GF(2⁸) (the AES field, poly `0x11B`):
  `xtime`, `mul`, `inv`. Used **only at table-build time**.
- `src/wbaes/aes_ref.{h,cpp}` — a textbook AES-128 (S-box built from
  `inv` + the affine map, key expansion, encrypt). This is a **test oracle
  only** — the white-box must reproduce its output. Anchored to the FIPS-197
  known-answer vector.

### 3.2 The table decomposition

A normal AES round is `SubBytes → ShiftRows → MixColumns → AddRoundKey`. Chow
re-associates this into three table types (`src/wbaes/aes_tables.*`):

- **T-boxes** — fold `AddRoundKey` + `SubBytes` into one 8→8 table per state
  byte: `T(x) = SBox[x ⊕ k]`. Round key `k_m` is baked in here — this is where
  the key lives. The final round's T-box also folds the last round key `k10`
  (past ShiftRows), so no key material is ever added outside a table.
- **Tyi tables** — decompose `MixColumns` (a GF(2⁸) matrix multiply on each
  4-byte column) into four 8→32 tables whose XOR reconstructs the column. All the
  field multiplication is precomputed here.
- **Type-IV XOR tables** — because intermediate values are *encoded* (see below),
  you can't just XOR them with a machine `^`. Each XOR of two encoded bytes is a
  pair of 4-bit table lookups (one per nibble). These fold the four Tyi outputs of
  a column together.

At **runtime the network does only table lookups and XORs — no GF math**. That
invariant is the correctness anchor for the whole project: if the runtime ever
needed a multiply, something is wrong.

### 3.3 Encodings (why the key hides)

Every intermediate byte is wrapped in a random **8-bit encoding** = two
independent 4-bit nibble bijections (`src/wbaes/encodings.*`, `ByteEnc`,
`Nibble`, seeded by a `splitmix64` `Rng`). Each table is built to *decode* its
inputs and *re-encode* its outputs, so consecutive tables' encodings **cancel**
while the plaintext intermediate values are never exposed. The nibble split is
exactly what makes the type-IV XOR tables small (256 entries).

Two build levels (`WBLevel`):
- **`Naked`** — all encodings identity. Computes plain AES; used to test the raw
  table decomposition in isolation.
- **`Internal`** — random nibble encodings everywhere; the shipped level.

**External encodings are the identity** (input/output not encoded), which is a
deliberate choice: it makes the white-box a **drop-in AES-128** whose output
equals the FIPS vector directly. (A stronger "mixing bijection" level was
evaluated and deliberately deferred — see [§13](#13-design-decisions--rationale)
and [THREATMODEL.md](THREATMODEL.md).)

### 3.4 Building and evaluating

- `src/wbaes/wb_generator.{h,cpp}` — `GenerateWhiteBox(key, seed, level)` walks
  the rounds, assigns an encoding to every byte "wire" (`OUT`/`TB`/`TY`/`W1`/`W2`
  arrays), and fills the tables so encodings cancel. Returns a heap-allocated
  `WhiteBox` (~1.5 MB). This is the "trusted storage producer" — the key is
  consumed here and never stored again.
- `src/wbaes/wb_interp.{h,cpp}` — `WhiteBoxEncrypt(wb, block)` evaluates the
  network in plain C++. **This is the reference the VM is differential-tested
  against.** The per-round data flow:

  ```
  for round m in 0..8:                       (AES rounds 1..9)
      t[i]      = tbox[m][i][ state[i] ]                 # T-box
      for each column c, lane j in 0..3:
          gather ty[mm] = ty[m][4c+mm][ t[ShiftRowsSrc(4c+mm)] ]   # ShiftRows + Tyi
          s = XorEncoded( xr[m][c][j][0], ty0[j], ty1[j] )        # type-IV XOR tree
          s = XorEncoded( xr[m][c][j][1], s,      ty2[j] )
          s = XorEncoded( xr[m][c][j][2], s,      ty3[j] )
          out[4c+j] = s
      state = out
  final round m=9:                           (AES round 10, no MixColumns)
      t[i]   = tbox[9][i][ state[i] ]
      ct[dst]= t[ ShiftRowsSrc(dst) ]         # k10 already folded into tbox[9]
  ```

`ShiftRowsSrc(dst)` (in `aes_tables.h`) is the column-major routing that makes
ShiftRows a pure wiring permutation between the T-box and Tyi stages.

---

## 4. Layer 2 — The virtual machine

**Goal:** run the table network as a program on a custom CPU so a static viewer
sees a generic interpreter, not AES.

### 4.1 Instruction set (`src/vm/isa.h`)

A tiny 32-bit **register machine**, 16 registers, 19 opcodes — deliberately
generic (no crypto-specific ops):

```
HALT  LDI  MOV  LDB  STB  XOR  AND  OR  ADD  SUB  NOT  SHL  SHR  PUSH  POP  JMP  JZ  JNZ  DECJNZ
```

`LDB rd, rbase, roff` (`reg[rd] = data[reg[rbase]+reg[roff]]`) is the workhorse:
a table lookup is just an indexed load. `SUB`/`NOT` exist to support MBA and
opaque predicates.

### 4.2 Harvard memory model (`src/vm/vm.h`)

The VM keeps **separate memories** (not one flat buffer):

- **CODE** — the encrypted bytecode (`Program.code`), addressed by `vip`.
- **DATA** — the table bank + I/O scratch (`VMContext.data`, a private per-run
  copy of `Program.data`).
- **STACK** — a separate `std::vector<uint32_t>` for `PUSH`/`POP`.
- **registers** — `reg[16]`.

DATA memory layout (constants in `src/vm/assembler.cpp`):

```
 offset 0        : TBOX region   10*16*256   = 40960 B
 offset 40960    : TY region      9*16*256*4 = 147456 B
 offset 188416   : XR region      9*4*4*3*2*256 = 221184 B
 offset 409600   : STATE (16 B)   ← input block written here, output read here
 offset 409616   : TMP   (16 B)   ← T-box outputs
 offset 409632   : OUT   (16 B)   ← per-round output
 total 409648 B
```

### 4.3 Compiling tables → bytecode (`src/vm/assembler.cpp`)

`AssembleWhiteBox(wb, seed, obf)` does three things:

1. **Serializes the table bank** into the DATA image at the offsets above.
2. **Emits generic bytecode** that reproduces `wb_interp` step for step, using
   fixed scratch registers. Each table lookup becomes `LDI base; LDB`; each
   encoded byte-XOR becomes `XorNibble(...)` — a ~15-instruction sequence of
   shifts/ands/ors + two table lookups. The whole encryption is emitted
   straight-line (~thousands of instructions).
3. Hands the **plaintext** bytecode to the firmware encryptor (§5) and returns a
   finished `vm::Program`.

Three obfuscation layers are woven in during emission (`ObfOptions`):

- **Opcode blinding** (`src/obf/blinding.*`) — each logical opcode is assigned
  3–5 *physical* byte values; `op()` picks one at random per emission, so the same
  operation is spelled many ways and the opcode histogram is flat.
- **MBA** (`src/obf/mba.h`) — the index arithmetic inside `XorNibble` is randomly
  rewritten via identities like `x|y == (x^y)+(x&y)`, using the VM's own ops.
  (Applied to the *bytecode*, not the C++ — a source-level identity would be
  folded back by the compiler.)
- **Opaque predicates** (`src/obf/opaque.h`, `EmitOpaqueGuard`) — between rounds,
  an always-true test (`x | ~x != 0`) guards a **junk block** that is jumped over
  at runtime, injecting dead code and bogus control flow.

### 4.4 Fetch-decode-execute (`src/vm/vm.cpp`, `src/vm/handlers.cpp`)

`Run(prog, block)` copies the DATA image, writes the input block to STATE, then
loops:

```
while not halted:
    ip = vip
    (set up this instruction's decode key — see §5)
    phys   = FetchByte()                 # decode-on-fetch
    logical= phys_to_op[phys]            # undo opcode blinding
    handlers[logical](ctx)               # the handler fetches its own operands
    (evolve the decode key — see §5)
```

`Handlers()` is the dispatch table (one function per logical op). Handlers fetch
operands through `Rf()`, which **masks register indices into `[0,16)`** — so a
garbage-decoded operand (e.g. after tampering) yields *wrong output*, never an
out-of-bounds crash. Data addresses and the step counter are bounds-checked too.
Output is read back from STATE.

---

## 5. Layer 3 — Context-keyed firmware

**Goal:** the bytecode has **no stored decryption keystream**, decodes with a key
that **evolves as it executes**, is **bound to the interpreter's identity**, and
**cascades to garbage on any tamper**.

### 5.1 The schedule (`src/fw/fw_schedule.h`) — one source of truth

Shared, header-only math used identically by the encryptor and the CPU:

- `PrfSeed(root, key_reg, ip)` — seeds a per-instruction keystream (`splitmix64`).
- `FoldInit` / `FoldByte` — an FNV-1a rolling checksum over an instruction's bytes.
- `UpdateKeyReg(key_reg, fold, ip)` — evolves the key after each instruction.
- `kInterpFingerprint` + `InterpFingerprint(op_to_phys)` — hashes a fixed
  per-opcode identity table together with the live opcode map. Folded into the
  root at run time (never stored), so re-mapping opcodes / patching the
  interpreter changes the effective key and breaks all decode.
- `DeriveRoot(seed)` — the stored root key.

Effective root = `fw_root ^ InterpFingerprint(op_to_phys)`.

### 5.2 The encryptor (`src/fw/fwcrypt.cpp`)

`EncryptFirmware(assembled, seed)` receives the plaintext bytecode plus, from the
assembler, the **instruction spans** and the **junk ranges** (the dead
opaque-guard blocks). It walks instructions in address order — which equals
execution order because guards jump *forward* over their junk — and for each:

- **executed** instruction at `ip`: derive `Rng(PrfSeed(eff_root, key_reg, ip))`,
  XOR each byte, fold the plaintext bytes, then `key_reg = UpdateKeyReg(...)`.
- **junk** instruction: encrypt with an independent filler stream and do **not**
  advance `key_reg` (the runtime never decodes these bytes).

Only `fw_root` (not the fingerprint, not any keystream) ends up in the `Program`.

### 5.3 Decode at run time (`src/vm/vm.cpp`)

The dispatcher mirrors the encryptor exactly. At each instruction it resets
`ctx.ks = Rng(PrfSeed(eff_root, key_reg, ip))` and `ctx.fold`; `FetchByte` returns
`code[vip] ^ ks.next()` and folds the decoded byte; after the handler runs,
`key_reg = UpdateKeyReg(key_reg, fold, ip)`.

**Why it's tamper-evident:** the fold is over *decoded* bytes. Flip any code byte
→ that instruction's decoded bytes differ → its fold differs → `key_reg` diverges
→ every later instruction decodes to garbage. Change the opcode map → the
effective root differs → decode fails from instruction zero. Both are proven in
`tests/test_fw.cpp` (early/mid/late byte flips and an opcode swap).

---

## 6. Layer 4 — Trusted storage

**Goal:** the on-disk blob keeps the tables encrypted at rest and is
tamper-evident, without a separate MAC.

`src/storage/trusted_storage.cpp` — `Seal(program, passphrase)` /
`Unseal(blob, passphrase, out)`. Blob format (little-endian):

```
magic "WBTS" | version | block_off | code_len | data_len | fw_root(8) |
phys_to_op(256) | op_to_phys(256) | code[code_len] | sealed_data[data_len]
```

- **Storage key** = a lightweight KDF (FNV hash of the passphrase ⊗ a domain
  constant). *Not* a real PBKDF — see the threat model.
- **Integrity binding (anti-tamper):** `LogicTag` = hash of the program *logic*
  (`block_off`, `fw_root`, both opcode maps, the code). The table data is
  stream-sealed under `storageKey ^ LogicTag`. So editing the code or the maps
  changes the tag → the tables decrypt to garbage → wrong output. This is
  anti-tamper *by binding*, not an authentication check you could bypass.

A wrong passphrase (or a tampered blob) does **not** error — it yields a program
that runs and produces wrong ciphertext, by design (no oracle for the attacker).

---

## 7. Layer 5 — The C-ABI SDK

**Goal:** embed the whole thing in any native project.

- `include/wbcrypto.h` — the stable C ABI (opaque `wbc_ctx`, `wbc_status`).
- `src/sdk/wbcrypto.cpp` — a thin wrapper; every entry point is a **noexcept
  boundary** (C++ exceptions are caught and mapped to status codes).

Surface:

```
wbc_seal_key(key, pass, seed, hardened, &blob, &len)   # offline: key → sealed blob
wbc_export_tables(key, seed, &image, &len)             # offline: key → freestanding image
wbc_open(blob, len, pass, &ctx)                        # runtime: load a blob
wbc_encrypt_block(ctx, in16, out16)                    # one ECB block
wbc_encrypt_ecb(ctx, in, out, len)                     # many ECB blocks
wbc_crypt_ctr(ctx, iv16, in, out, len)                 # CTR: encrypts AND decrypts
wbc_close / wbc_free
```

`wbc_ctx` simply owns a `vm::Program`; `wbc_encrypt_block` calls `vm::Run`.
**CTR mode** turns the encrypt-only white-box into a full stream cipher (the same
call enciphers and deciphers arbitrary-length data), which is what real payload
use needs. Ships as `libwbcrypto.a` and `libwbcrypto.so`.

---

## 8. Layer 6 — Freestanding device runtime

**Goal:** decrypt on a device with **no libc, no malloc, no dynamic loader** —
e.g. an injected packer stub — where the C++ SDK cannot run.

- `freestanding/wb_table_layout.h` — the flat **table-image** format (a 12-byte
  header + the T-box/Tyi/XOR regions, `WBTB_IMAGE_SIZE == 409612`). Shared with
  the host exporter `src/wbaes/wb_export.cpp` (`ExportTableImage`).
- `freestanding/wb_stub.h` — header-only `wbstub_encrypt_block` and
  `wbstub_ctr_xcrypt`. Pure C, no libc, no allocation, **no function pointers**
  (relocation-free), small fixed stack arrays only. It runs the *same table
  network* as `wb_interp`, read straight from the image.

Crucially the device path runs the **tables directly** — it does **not** include
the VM, the bytecode, or the context-keyed firmware (those need mutable memory
and a full runtime). So on device you get *key diffusion* but not the VM/firmware
static-hardening. A build gate (`freestanding/selftest.c` + `build.sh`) compiles
the runtime with `-ffreestanding -nostdlib -fno-builtin` and **fails if any libc
call is emitted**.

---

## 9. End-to-end data flow

### Offline (key known, on a trusted host)

```
key ─► GenerateWhiteBox ─► WhiteBox ─► AssembleWhiteBox ─► (plaintext bytecode
                                          │                  + DATA image + spans/junk)
                                          ▼
                                     EncryptFirmware ─► vm::Program ─► Seal ─► blob
                                          │
                       (or) ExportTableImage ─► lib.wbt  (for the freestanding stub)
```

### Runtime — VM path (host / SDK / CLI)

```
blob ─► Unseal ─► vm::Program ─► Run:
          │                        for each instruction:
          │                          derive per-instr keystream (evolving key)
          │                          FetchByte = code ^ keystream; decode opcode
          │                          handler: table lookups (LDB) + encoded XOR
          │                          evolve key_reg
          ▼
      ciphertext == standard AES-128
```

### Runtime — freestanding path (device stub)

```
lib.wbt ─► wbstub_ctr_xcrypt(tables, iv, buf, buf, len) ─► decrypted payload
           (direct table lookups + XOR; no VM, no firmware)
```

---

## 10. Key data structures

| Type | Where | Role |
|------|-------|------|
| `wbaes::WhiteBox` | `wbaes/wb_generator.h` | The table network: `tbox[10][16]`, `ty[9][16]`, `xr[9][4][4][3][2]`. ~1.5 MB, heap. |
| `wbaes::ByteEnc` / `Nibble` | `wbaes/encodings.h` | 8-bit encoding = two 4-bit bijections + inverses. |
| `wbaes::Rng` | `wbaes/encodings.h` | `splitmix64` PRNG; drives encodings, blinding, and the firmware keystream. |
| `vm::Program` | `vm/vm.h` | Runnable image: encrypted `code`, `fw_root`, opcode maps, DATA image, `block_off`. Serialized into the blob. |
| `vm::VMContext` | `vm/vm.h` | Live state: DATA copy, `reg[16]`, stack, `vip`, and the decode state (`eff_root`, `key_reg`, `ks`, `fold`). |
| `fw::AssembledProgram` | `fw/fwcrypt.h` | Plaintext bytecode + instruction spans + junk ranges, handed from assembler to encryptor. |
| `vm::ObfOptions` | `vm/assembler.h` | Toggles blinding / MBA / opaque predicates. |
| `wbc_ctx` | `sdk/wbcrypto.cpp` | Opaque SDK handle; owns a `vm::Program`. |

---

## 11. Sizes and numbers

| Thing | Value |
|-------|-------|
| AES | 128-bit key, 16-byte block, 10 rounds |
| Registers / opcodes | 16 × 32-bit / 19 |
| White-box tables (in memory) | ~1.5 MB (`WhiteBox`) |
| VM DATA image | 409,648 B (tables + 3×16 B scratch) |
| Freestanding table image | 409,612 B (`WBTB_IMAGE_SIZE`) |
| Hardened bytecode | ~58 KB, entropy ≈ 7.997 bits/byte |
| Sealed blob (hardened) | ~468 KB |
| FIPS-197 anchor | key `000102…0f`, pt `001122…ff` → ct `69c4e0d8…c55a` |

---

## 12. Verification strategy

The design is testable because it's **layered and differential** — every layer is
checked against a simpler, already-trusted layer, all gated on the FIPS vector +
random keys/blocks:

- `test_aes_ref` — the oracle vs FIPS-197 (trust nothing until this passes).
- `test_wbaes` — white-box == AES at **each stratum** (Naked, Internal), so an
  "encodings don't cancel" bug localizes to one layer.
- `test_vm` — VM output == `wb_interp` == AES (plain and hardened bytecode). Same
  verified table blob feeds both, so a mismatch is a VM bug, never a crypto bug.
- `test_obf` — every MBA identity over 200k random pairs; the opaque predicate;
  opcode-blinding disjointness (each primitive proven before it's used).
- `test_fw` — context decode == AES; **byte-tamper cascade**; **interpreter
  binding**; high entropy; no stored keystream.
- `test_stub` — the freestanding runtime == AES from an exported image (+ CTR
  round-trip); plus a compile-time no-libc gate.
- `test_e2e` — seal→unseal→run == AES; **key absence** (no key/round-key bytes in
  the blob or decrypted tables); **anti-tamper** (code-byte flip / wrong
  passphrase → wrong output, and the integrity binding is shown to have fired).

---

## 13. Design decisions & rationale

- **External encodings = identity** → drop-in AES-128, so the FIPS vector is a
  direct correctness anchor. The internal encodings still provide the round-to-
  round obfuscation.
- **Runtime = lookups + XOR only** → keeps the VM ISA tiny and acts as a
  standing correctness invariant.
- **VM executes the *same* verified table blob** the interpreter does →
  cleanly separates crypto bugs from VM bugs via differential testing.
- **MBA/opaque applied to bytecode, not C++ source** → survives the optimizer
  (source-level MBA would be folded back to a single op).
- **Context-keyed firmware over a stored keystream** → removes the "keystream
  next to the code" weakness and buys runtime anti-tamper for free.
- **Register-index masking in handlers** → tampering degrades to wrong output,
  never a crash (essential once decode cascades).
- **32-bit mixing bijections deliberately *not* implemented** → a version that
  cancels within a round adds no BGE resistance (and the `==AES` test can't even
  tell), and a faithful version is exactly what BGE was built to break — real
  complexity for a bounded, unverifiable, still-breakable margin. Documented as
  future work in [THREATMODEL.md](THREATMODEL.md) instead.
- **No third-party dependencies**; builds with a bootstrapped `zig c++` toolchain
  when no system compiler exists (see [BUILD.md](BUILD.md)).

---

*For what all of this does and does **not** protect against, read
[THREATMODEL.md](THREATMODEL.md). For the source material (Tim Blazytko's
obfuscation/deobfuscation deck) see `assets/tim-slide.pdf`.*
