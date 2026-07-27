# Usage Guide

Two ways to use the White-box Crypto VM: the **CLI tools** (seal a key, then
encrypt), and the **C++ library API** (embed it in your own program).

The key is consumed only by `wb_keygen`/`GenerateWhiteBox`. From then on it lives
only diffused inside the sealed blob — it is never written out and never
reconstructed at runtime.

---

## 1. CLI workflow

### Step 1 — seal a key into a trusted-storage blob

```sh
./build/wb_keygen --key <32 hex chars> [--pass <phrase>] [--seed N] [--plain] --out FILE
```

| Flag       | Meaning                                                                 |
|------------|-------------------------------------------------------------------------|
| `--key`    | the AES-128 key as 32 hex characters (16 bytes). **Required.**           |
| `--out`    | path to write the sealed blob. **Required.**                            |
| `--pass`   | passphrase that seals the table bank at rest (default: empty).           |
| `--seed`   | integer seed for the white-box encodings + obfuscation (default fixed).  |
| `--plain`  | disable bytecode obfuscation (bare VM, for study/debugging).             |

```sh
./build/wb_keygen \
  --key 000102030405060708090a0b0c0d0e0f \
  --pass "correct horse battery staple" \
  --out wb.blob
# -> sealed white-box -> wb.blob (468112 bytes, hardened bytecode, 57924 B code)
```

The blob contains the context-encrypted VM firmware plus the sealed table
network. It does **not** contain the key (see key-absence check below), and it
must not be edited: the firmware decode is tamper-chained, so flipping any byte
of the blob makes it produce wrong output (see anti-tamper below).

### Step 2 — encrypt a block through the sealed VM

```sh
./build/wb_encrypt --in FILE [--pass <phrase>] --pt <32 hex chars>
```

| Flag       | Meaning                                              |
|------------|------------------------------------------------------|
| `--in`     | the sealed blob from `wb_keygen`. **Required.**      |
| `--pt`     | the 16-byte plaintext block as 32 hex chars.         |
| `--pass`   | the passphrase used at seal time.                    |

```sh
./build/wb_encrypt --in wb.blob \
  --pass "correct horse battery staple" \
  --pt 00112233445566778899aabbccddeeff
# -> 69c4e0d86a7b0430d8cdb78070b4c55a
```

Output is one 16-byte AES-128 ciphertext block in hex. With external encodings =
identity, it equals a standard AES-128 encryption of the same key and block, so
you can verify it against any AES implementation (this is the FIPS-197 vector).

### Encrypting more than one block

Each `wb_encrypt` call does one 16-byte block (ECB semantics). For a stream,
call it per block, or use the library API and drive `vm::Run` in a loop with
your own mode of operation (CTR/CBC) around it.

---

## 2. Observable properties (what makes it a white-box / trusted store)

```sh
# The raw key never appears in the blob:
xxd wb.blob | grep -i "0001 0203 0405 0607" || echo "key not found in blob ✓"

# Wrong passphrase does not leak the correct ciphertext — it yields garbage:
./build/wb_encrypt --in wb.blob --pass wrong --pt 00112233445566778899aabbccddeeff
# -> 323997cf54a7f07a4ee47cf1b0cc2950   (≠ the real ciphertext)
```

- **Key diffusion:** the key is spread across the T-box / Tyi / XOR tables; no
  round key exists as contiguous bytes anywhere in the blob or the runtime data.
- **Static opacity:** the firmware is context-keyed (no stored keystream) with
  opcode blinding, so a disassembler sees ~8 bits/byte of entropy — no
  recognizable structure and nothing to decode statically.
- **Anti-tamper (two ways):** the runtime decode key evolves with execution and
  is bound to the interpreter fingerprint, so flipping any code byte — or
  re-mapping opcodes — cascades into garbage; and at rest, an integrity tag over
  the firmware is folded into the data-decrypt key, so tampering the sealed blob
  corrupts the tables too.

See [SDK.md](SDK.md) for embedding, and **[THREATMODEL.md](THREATMODEL.md)** for
the honest, layer-by-layer analysis — this raises the bar against *static*
analysis and *tampering*, but does not stop a dynamic attacker and does not make
the key cryptographically secret (Chow's white-box is academically breakable).

---

## 3. Library API

Include headers from `src/` and link against the library sources (or the `wbvm`
target under CMake). The full pipeline is four calls:

```cpp
#include "wbaes/wb_generator.h"   // GenerateWhiteBox, WBLevel, Key128
#include "vm/assembler.h"         // AssembleWhiteBox, ObfOptions
#include "vm/vm.h"                // Program, Run
#include "storage/trusted_storage.h"  // Seal, Unseal

using namespace wbaes;

// --- offline: compile a key into a sealed blob ---------------------------
Key128 key = { /* 16 bytes */ };
auto wb   = GenerateWhiteBox(key, /*seed=*/12345, WBLevel::Internal);
auto prog = vm::AssembleWhiteBox(*wb, /*seed=*/999, vm::ObfOptions::All());
std::vector<uint8_t> blob = storage::Seal(prog, "my-passphrase");
// ... persist `blob` ...

// --- runtime: unseal and encrypt -----------------------------------------
vm::Program loaded;
if (!storage::Unseal(blob, "my-passphrase", loaded))
    return /* malformed blob */;

std::array<uint8_t,16> pt = { /* plaintext block */ };
std::array<uint8_t,16> ct = vm::Run(loaded, pt);   // encoded table lookups inside the VM
```

### Key types & knobs

| Symbol                                   | Notes |
|------------------------------------------|-------|
| `wbaes::WBLevel::Naked`                  | no encodings — plain AES in table form (study/debug only). |
| `wbaes::WBLevel::Internal`               | random 4-bit encodings; the level you should ship. |
| `vm::ObfOptions::All()` / `::None()`     | toggle handler duplication + MBA + opaque predicates. |
| `vm::ObfOptions{ .handler_duplication=…, .mba=…, .opaque_predicates=… }` | pick layers individually. |
| `storage::Seal` / `storage::Unseal`      | at-rest sealing + integrity binding under a passphrase. |

### Correctness anchor

`GenerateWhiteBox(..., Internal)` + identity external encodings reproduces
standard AES-128. To self-check, compare `vm::Run` against the bundled reference
oracle:

```cpp
#include "wbaes/aes_ref.h"
assert(vm::Run(loaded, pt) == /*as array*/ AesEncryptBlock(pt, key));
```
