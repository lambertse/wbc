# Threat Model

This project is an **educational / research artifact**. It raises the *practical*
bar against several classes of attacker, but it is **not an unbreakable key
vault**. This document states precisely what each layer does and — just as
importantly — what it does **not** do, so the guarantees are never overclaimed.

## One-line summary

The AES key is never a contiguous byte string and never materializes at runtime;
recovering it requires **cryptanalysis of the white-box tables**, not a memory
scan. Everything else (VM virtualization, context-keyed firmware, sealing) raises
the cost of **static analysis and tampering** — none of it makes the key
cryptographically secret, and none of it stops an attacker who can **run and
trace** the code.

## Layers and what each is worth

| Layer | Raises the bar against | Does **not** help against |
|-------|------------------------|---------------------------|
| **White-box AES (Chow, internal-encoding level)** | Reading the key from memory/disk — it is diffused across T-box/Tyi/XOR tables, never contiguous | **Key extraction by cryptanalysis** — BGE / Billet et al. recover the key from the tables. This is the hard ceiling. |
| **VM virtualization** (custom ISA, FDE dispatcher, handler table) | Recognizing the algorithm as AES from a static disassembly | Someone who runs/traces the VM (the program is straight-line and data-oblivious, so one trace reveals it) |
| **Opcode blinding, MBA, opaque predicates** | Static pattern-matching of opcodes and operations | Dynamic analysis; the crypto key |
| **Context-keyed firmware encryption** (W1) | Lifting a stored keystream (there is none); bulk static decode (decode evolves with execution); **tampering** (any code-byte or opcode-map edit cascades to garbage) | Dynamic tracing (hook the decode / run once); the crypto key |
| **Trusted-storage sealing** | Reading the tables at rest (stream-encrypted); silent tampering (integrity binding corrupts output) | Cryptographic secrecy — everything needed to run is in the blob; the KDF is a lightweight hash, not a PBKDF/AEAD |
| **Freestanding device runtime** (`wb_stub.h`) | Shipping a raw key in a packer/APK — the key is diffused in the injected table image | Cryptanalysis (same Chow ceiling); it deliberately omits the VM/firmware layers (runs tables directly) |

## Attacker capabilities

- **Static-only (disassembler, hex editor, no execution).** Faces the full
  stack: virtualized + blinded + MBA + opaque + context-encrypted firmware whose
  bytecode is ≈ 8 bits/byte entropy with no liftable keystream, over a diffused
  key. This is where the project is strongest.
- **Tampering (patch the binary/blob).** Any edit to a code byte, the opcode
  map, or (at rest) the sealed tables cascades into wrong output — tamper-evident
  by construction (runtime feedback cascade + at-rest integrity binding). This is
  anti-tamper, **not** authentication.
- **Dynamic (run, trace, hook, debug).** **Largely wins.** The white-box program
  is straight-line and data-oblivious, so a single trace (or a hook on the decode
  fetch) recovers the decoded program regardless of the firmware encryption. We
  do not implement anti-debug, data-dependent control flow, or interpreter
  self-integrity at runtime.
- **Cryptanalyst.** **Wins the key.** Chow-family white-boxes are academically
  broken (BGE, Billet et al.). Obfuscation raises the effort to *set up* the
  attack, not its fundamental feasibility.

## Deliberately deferred / future work

- **32-bit mixing bijections (Chow type II/III).** Considered and **not shipped**.
  A version that applies and inverts the bijection within a round *cancels before
  the round boundary* and adds no BGE resistance — and our `== AES` test cannot
  distinguish it from a no-op. A faithful version (fusing `MB⁻¹` into the next
  round's T-box) is **exactly the construction BGE was designed to defeat**: it
  moves the key from "extractable" to "extractable with more work," never to
  "secret." Given the cost (a doubled table network across four runtime paths
  including the freestanding stub) versus that bounded, unverifiable payoff, it is
  documented here rather than implemented.
- **Dynamic-analysis resistance.** Anti-debugging, data-dependent control flow,
  runtime interpreter self-integrity, timing checks. Large, OS/arch-specific, and
  with a known ceiling (VMs are deobfuscatable via symbolic execution + program
  synthesis — the thesis of the source deck).
- **Genuinely key-hardening constructions.** Space-hard / incompressible
  white-boxes (e.g. SPACE-family) argue *code-lifting* resistance rather than key
  secrecy — a different security model and a much larger build.
- **Real at-rest crypto.** Replace the lightweight KDF/stream seal with a proper
  PBKDF/Argon2 + AEAD if the blob must resist offline attack on the passphrase.

## Bottom line

Use this to make "grep the binary for the key" fail and "patch the decryptor"
fail. Do **not** use it where a motivated attacker who can run the code, or a
cryptanalyst, must be kept from the key — the underlying white-box cannot provide
that, and no obfuscation layer here changes it.
