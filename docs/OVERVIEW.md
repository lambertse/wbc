# Project Overview

*Start here if you've never seen this project — no cryptography or reverse-
engineering background assumed. For the deep implementation, read
[ARCHITECTURE.md](ARCHITECTURE.md) next.*

---

## 1. What is this?

A small system that lets a program **encrypt data with AES-128 without ever
holding the AES key in a form an attacker can read** — even if the attacker owns
the machine, has the binary, and can inspect its memory.

It does this by turning "AES + a specific key" into a big pile of **lookup
tables**, running those tables inside a **custom virtual machine (VM)** whose
program is itself encrypted, and packaging the whole thing as a sealed file (a
"blob") plus a couple of tools and a C library to use it.

## 2. The problem it solves

Normal cryptography assumes the key is secret and the attacker only sees inputs
and outputs (the "black box" model). But lots of real software runs on devices
the attacker controls — think DRM, mobile apps, game clients, or a packed
library. There, the attacker can pause the program and dump memory. A normal AES
implementation keeps `key` in a variable; one memory dump and it's gone.

**White-box cryptography** is the field that asks: *can we implement a cipher so
that even someone watching every instruction and byte of memory can't easily
extract the key?* This project is a hands-on, honest implementation of one such
scheme, wrapped in extra software-protection layers.

## 3. Three ideas you need

### Idea A — White-box AES (the key becomes tables)

Instead of `ciphertext = AES(key, plaintext)` computed with the key in a
register, you **precompute** AES-for-this-one-key as a network of ~160 lookup
tables. The key is mathematically *dissolved* into the table contents (mixed with
AES's S-box and round constants) and scrambled with random "encodings" that
cancel out as data flows through. The tables produce correct AES output, but the
key never appears as bytes anywhere. This is the **Chow construction** (2002).

> Think of it like a player piano roll: the "song" (your key) isn't stored as
> sheet music you can read — it's punched into a long roll of holes that only
> makes sense as it's played.

### Idea B — Virtualization (hide the program behind an interpreter)

Even with the key in tables, the *sequence of table lookups* reveals it's AES. So
we hide that logic inside a **virtual machine**: a made-up CPU with its own
instruction set. The real work is compiled to **bytecode** for this fake CPU, and
a small interpreter ("the VM") executes it. A reverse-engineer now sees a generic
interpreter chewing on unfamiliar bytecode, not recognizable AES. This is the
classic **VM-based obfuscation** technique (from Tim Blazytko's deck, the
project's source material).

### Idea C — Encrypted, tamper-evident firmware

The bytecode itself is **encrypted with an evolving key** that changes as the
program runs and is tied to the interpreter's own identity. There is no stored
"decryption key" to find; the decode key regenerates itself during execution. A
useful side effect: if anyone patches a single byte of the bytecode (or the
interpreter), the evolving key diverges and everything after it decodes to
garbage — **tamper-evidence for free**.

## 4. The big picture

```
   OFFLINE (once, on a trusted machine)                RUNTIME (on the device)
   ─────────────────────────────────────               ────────────────────────
   AES key (16 bytes)
        │
        ▼  Chow white-box compiler  (src/wbaes/)
   table network  ── key diffused into ~160 tables
        │
        ▼  assembler  (src/vm/)
   VM bytecode  ── table lookups expressed as a fake-CPU program
        │
        ▼  firmware encryptor  (src/fw/)
   context-encrypted bytecode  ── no stored keystream, tamper-chained
        │
        ▼  trusted-storage sealer  (src/storage/)
   sealed blob ────────────────────────────────►  open + run in the VM
   (tables encrypted at rest,                       │
    integrity-bound)                                ▼
                                              ciphertext  (== standard AES-128)
```

Everything left of the arrow happens once, offline, where the key is known.
Everything right of it ships to the untrusted device, which can *encrypt* but can
never *read the key*.

## 5. What you can actually run

| You want to…                                  | Use                               |
|-----------------------------------------------|-----------------------------------|
| Seal a key and encrypt from the command line  | `wb_keygen` / `wb_encrypt` ([BUILD.md](BUILD.md)) |
| Embed it in a C/C++/JNI/Rust/Go app           | the C library `libwbcrypto` ([../include/wbcrypto.h](../include/wbcrypto.h)) |
| Build everything                              | `./build.sh` ([BUILD.md](BUILD.md)) |

A useful sanity check: because the scheme is arranged to be **drop-in AES-128**,
encrypting the FIPS-197 test block always yields `69c4e0d8…c55a` — the exact same
answer any standard AES library gives. The obfuscation changes *how* it's
computed, never *what* it computes.

## 6. Honest limits (please read)

This raises the **practical** bar; it is **not** an unbreakable vault. Two hard
truths, expanded in the README's
[Threat model & honest limitations](../README.md#threat-model--honest-limitations):

- **The key is not cryptographically secret.** Chow's white-box is academically
  broken (the "BGE attack"): a determined cryptanalyst can extract the key from
  the tables. What we buy is that it takes *cryptanalysis*, not a memory scan.
- **It does not stop a dynamic attacker.** The program runs the same steps every
  time, so someone who can *run and trace* it can recover the logic. The
  obfuscation and firmware encryption defeat *static* inspection and *tampering*,
  not live tracing.

Used for what it's good at — making "grep the binary for the key" and "patch the
decryptor" both fail — it's a solid, faithful implementation.

## 7. Mini-glossary

- **AES-128** — the standard symmetric cipher; 16-byte key, 16-byte blocks, 10 rounds.
- **White-box** — an implementation meant to resist an attacker who sees everything.
- **Chow construction** — the specific 2002 white-box-AES design used here (lookup-table network with encodings).
- **T-box / Tyi / type-IV tables** — the three kinds of lookup tables the cipher is decomposed into (S-box+key, MixColumns, and XOR helpers).
- **VM / virtualization** — hiding logic behind a custom interpreter and bytecode.
- **Bytecode** — the fake-CPU program the VM executes.
- **Firmware (here)** — the (encrypted) bytecode image loaded into the VM.
- **Blob** — the sealed file holding the encrypted firmware + tables.
- **BGE attack** — the known cryptanalytic attack that extracts keys from Chow white-boxes.

## 8. Where to next

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — every component, data structure, and algorithm, with file references.
- **[BUILD.md](BUILD.md)** — how to compile, test, and drive the CLI tools.
- **[../include/wbcrypto.h](../include/wbcrypto.h)** — the C ABI for embedding the library.
- **[ANTI-TAMPER.md](ANTI-TAMPER.md)** — the native-code obfuscation (O-MVLL) hardening.
- **[Threat model](../README.md#threat-model--honest-limitations)** — what each layer does and does not protect.
