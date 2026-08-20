# The seal-blob flow (`wb_keygen`)

How one cleartext AES-128 key becomes a sealed `WBTS` blob, and how that blob is
opened again in the field. This document is the **provenance** reference: which
bytes in the blob come from the key, which from the provisioning seed, which from
the CSPRNG, and which are byte-identical if you re-run the same command.

For the pieces this deliberately does not restate, see
[ARCHITECTURE §3](../ARCHITECTURE.md) (the Chow table decomposition and
encodings), [§5](../ARCHITECTURE.md) (the context-keyed decode schedule) and
[§6](../ARCHITECTURE.md) (the blob format and the KDF cost tiers).

---

## 1. What it is, in one paragraph

`wb_keygen` is a **pack-host** tool, not a runtime one. It takes an AES-128 key
on the command line, compiles it into a Chow white-box table network, compiles
*that* into obfuscated bytecode for the project's VM, encrypts the bytecode with
a context-keyed schedule, and seals the result into a single file. The key is
consumed in the process and never written out in any form. The field runtime
(`wbc_open` + `wbc_wrap_key`) opens the blob and uses the white-box without ever
reconstructing the key. Sealing is a one-time offline operation; opening happens
on every app start.

`src/tools/wb_keygen.cpp` is the CLI; `wbc_seal_key`
(`src/sdk/wbcrypto_provision.cpp`) is the same flow behind the C ABI (§7).

---

## 2. Input

```
wb_keygen --key <32 hex> [--pass <phrase>] [--seed N]
          [--kdf light|medium|heavy] --out FILE
```

| Flag | Required | Default | What it feeds |
|---|---|---|---|
| `--key` | **yes** | — | The AES-128 key, 32 hex chars. Consumed by `KeyExpansion` + `GenerateWhiteBox`; never stored. |
| `--out` | **yes** | — | Destination file. |
| `--pass` | no | `""` (empty) | The seal passphrase. Input to the KDF that produces the AEAD key. An empty passphrase is accepted **and there is no warning** — and since the salt is public (offset 12), an empty passphrase makes the seal key computable from the blob alone, at *every* tier including `heavy`. |
| `--seed` | no | `0xA5F00D` | Diversifies **everything deterministic**: the white-box encodings, the opcode blinding, the MBA/junk choices and `fw_root`. See §10. |
| `--kdf` | no | `heavy` | The KDF cost tier recorded in the blob. `light`→`KdfTier::kNone` (HKDF-SHA256), `medium`→`kLow` (Argon2id 16 MiB), `heavy`→`kHigh` (Argon2id 64 MiB). A typo is a usage error, never a silent fallback. |

Two deliberate absences:

* **There is no flag to disable bytecode hardening.** `wb_keygen` always passes
  `vm::ObfOptions::All()`. Its output is a shipping artifact, and a switch that
  quietly removes the obfuscation is only ever a way to ship an unhardened blob
  by accident. `ObfOptions::None()` still exists for the differential tests and
  for `wbc_seal_key`'s `hardened` parameter, neither of which writes a file you
  could ship unnoticed.
* **`--kdf` defaults to the most expensive tier**, so forgetting the flag cannot
  silently produce a blob with no passphrase-guessing resistance. Choosing
  `light` prints a warning to stderr.

---

## 3. The four compilation stages

### 3.1 Key → table network

`GenerateWhiteBox(key, seed, WBLevel::Internal)`
(`src/wbaes/wb_generator.cpp:34`)

`KeyExpansion(key)` produces the 11 AES round keys, then the generator builds a
~1.5 MB heap-allocated `WhiteBox`:

* **T-boxes** — `tbox[m][i][v] = enc(SBox[dec(v) ^ k_m[i]])` for rounds 1..9.
  `AddRoundKey` and `SubBytes` are fused, so the round key exists only *inside*
  the table. The final T-box (index 9) folds `k9` **and** `k10` (the latter past
  ShiftRows), so no key material is ever added outside a table.
* **Tyi tables** — `MixColumns` precomputed as four 8→32 lookups per column.
  All GF(2⁸) multiplication happens here, at build time; the runtime never
  multiplies.
* **Type-IV XOR tables** — because intermediates are *encoded*, XOR cannot be a
  machine `^`. Each XOR of two encoded bytes becomes two 256-entry nibble
  lookups, which fold a column's four Tyi outputs together in a 3-step tree.

Every intermediate wire gets a random 8-bit encoding (two independent 4-bit
bijections), and each table decodes its inputs and re-encodes its outputs so
consecutive encodings **cancel**. External encodings are the identity, which is
what makes the white-box a drop-in AES-128 matching the FIPS-197 vector directly.

### 3.2 Table network → bytecode + DATA image

`AssembleWhiteBox(*wb, seed ^ 0x9999, ObfOptions::All())`
(`src/vm/assembler.cpp:199`)

The assembler serialises the whole table bank into a flat **409,648-byte DATA
image**:

| Region | Offset | Size |
|---|---|---|
| T-boxes (10 rounds × 16 bytes × 256) | 0 | 40,960 |
| Tyi (9 × 16 × 256 × 4) | 40,960 | 147,456 |
| Type-IV XOR (9 × 4 × 4 × 3 × 2 × 256) | 188,416 | 221,184 |
| `STATE` (the live 16-byte block, in **and** out) | 409,600 | 16 |
| `TMP` / `OUT` scratch | 409,616 | 32 |

`STATE`'s offset is what lands in the header as `block_off`.

It then emits straight-line bytecode that walks the network step for step —
T-box lookup, ShiftRows-permuted Tyi gather, three nibble-XOR folds per lane,
state writeback — using immediate-base `LDBI`/`STBI` accesses so each constant
table base folds into the instruction. On top of that, three obfuscation layers,
all driven by the same seeded RNG:

* **handler duplication** — 3–5 distinct physical opcode bytes per logical
  opcode, picked at random per instruction, so the same operation is spelled many
  ways. The resulting permutation is the `op_to_phys` / `phys_to_op` pair.
* **MBA rewriting** — the index arithmetic's `OR`/`AND` are randomly replaced by
  identities such as `(x^y)+(x&y)` and `(x|y)-(x^y)`.
* **opaque predicates** — an always-taken `JNZ` (`x | ~x != 0`) jumps over a junk
  block that touches only dead scratch registers.

The preamble seeds *every* register with a distinct non-zero value before
overwriting the three that carry real constants. That is a tamper property, not
decoration: a flipped register-operand byte must change the computation, which it
cannot if two register indices happen to hold the same value.

### 3.3 Bytecode → encrypted firmware

`fw::EncryptFirmware(prog, seed ^ 0x9999)` (`src/fw/fwcrypt.cpp:16`)

`fw_root = DeriveRoot(seed ^ 0x9999)`, and the effective root folds in the
**interpreter fingerprint** — a hash of the fixed per-opcode identity constants
together with the live `op_to_phys` map. Each instruction is then XOR-encoded
with a fresh keystream seeded by `PrfSeed(eff_root, key_reg, ip)`, and after each
instruction `key_reg` absorbs a rolling fold over that instruction's *decoded*
bytes.

Consequences worth stating explicitly:

* **No keystream is stored anywhere.** The runtime regenerates it during fetch.
* **Any byte tamper cascades.** Flip a code byte → its decoded fold differs →
  `key_reg` diverges → every later instruction decodes to garbage.
* **Tampering the opcode map breaks decode from instruction zero**, because the
  map feeds the fingerprint that feeds the root.
* Junk ranges get an *independent* keystream and do **not** advance `key_reg` —
  the runtime never decodes them, so they must not be part of the chain.

### 3.4 Program → sealed blob

`storage::Seal(prog, passphrase, tier)`
(`src/storage/trusted_storage.cpp:168`)

1. Write magic, version, tier.
2. Draw a fresh 16-byte salt and 24-byte nonce from `randombytes_buf`.
3. Append `block_off`, `code_len`, `data_len`, `fw_root`, both opcode maps, and
   the encrypted bytecode.
4. Derive a 32-byte AEAD key from `(passphrase, salt)` at the chosen tier —
   HKDF-SHA256 for `kNone`, Argon2id otherwise.
5. `crypto_aead_xchacha20poly1305_ietf_encrypt` over **`prog.data` only**, with
   *everything written so far* as the associated data.
6. Append ciphertext + 16-byte tag, zero the key, return.

So the table bank is the only encrypted region, and the entire rest of the
program is authenticated in place. There is no separate MAC because the AEAD is
the MAC.

---

## 4. Output

One file. Layout (little-endian), with the offsets as they actually fall in a v4
blob:

| Offset | Field | Size |
|---|---|---|
| 0 | magic `"WBTS"` | 4 |
| 4 | `version` (currently **4**) | 4 |
| 8 | `kdf_tier` | 4 |
| 12 | `salt` | 16 |
| 28 | `nonce` | 24 |
| 52 | `block_off` | 4 |
| 56 | `code_len` | 4 |
| 60 | `data_len` | 4 |
| 64 | `fw_root` | 8 |
| 72 | `phys_to_op` | 256 |
| 328 | `op_to_phys` | 256 |
| 584 | `code` | `code_len` |
| 584 + `code_len` | `ciphertext` ‖ tag | `data_len` + 16 |

Measured on the committed `sealed.blob` (hardened, demo key, seed 42):

```
block_off = 409600   code_len = 44604   data_len = 409648
total     = 584 + 44604 + 409648 + 16 = 454,852 bytes  (444 KiB)
```

Verify any blob's header with:

```sh
od -A d -N 72 -t u4 sealed.blob     # words: magic, version, tier, salt…
```

**Encrypted:** the table bank only (`data_len` bytes — the diffused key).
**Authenticated but cleartext:** the header, `block_off`/`code_len`/`data_len`,
`fw_root`, *both* opcode maps, and all `code_len` bytes of bytecode. Cleartext
here means readable, not forgeable: editing any of it fails the tag.

---

## 5. Provenance — what is key-derived, seed-derived, or random

This is the table to read if you only read one thing.

| Artifact in the blob | Derived from | Identical when you re-seal with the same `--key`/`--seed`/`--pass`? |
|---|---|---|
| T-box entries | round keys (**key**) + encodings (**seed only**) | yes |
| Tyi tables | fixed MixColumns math + encodings (**seed**) | yes |
| Type-IV XOR tables | encodings (**seed**) | yes |
| bytecode (`code`) | `seed ^ 0x9999` (blinding, MBA, junk) + fw keystream | yes |
| `phys_to_op` / `op_to_phys` | `seed ^ 0x9999` | yes |
| `fw_root` | `DeriveRoot(seed ^ 0x9999)` | yes |
| `block_off`, `code_len`, `data_len` | fixed layout | yes |
| `version`, `kdf_tier` | format / `--kdf` | yes |
| `salt[16]`, `nonce[24]` | `randombytes_buf` (**CSPRNG**) | **no** |
| the AEAD/seal key | passphrase + salt, at tier cost | no (fresh salt each time) |
| `ciphertext` + tag | all of the above | no |

Read across that table:

* **The AES key is never stored, in any encoding.** It survives only diffused
  into the T-boxes (mixed with the S-box) and into the final round's folded
  `k10`. `tests/test_e2e.cpp` asserts that neither the key nor **any of the 11
  round keys** appears as a contiguous 16-byte string in the blob *or* in the
  decrypted table bank.
* **The seed is never stored either.** It is a provisioning input only. Note
  though that `op_to_phys` is a deterministic function of `seed ^ 0x9999` and
  sits in the cleartext associated data at offset 328 — see §10.
* **The passphrase is never stored.** Only its effect, via the derived key, on
  the ciphertext and tag.
* **The only true randomness in the file is the salt and the nonce** (40 bytes).
  Everything else is a deterministic function of the inputs.

One documentation wrinkle: `include/wbcrypto.h` says `seed` may be "0 for a
default", but `wbc_seal_key` passes it straight through
(`src/sdk/wbcrypto_provision.cpp:37`) with no zero-check. Seed 0 is just seed 0.
The `0xA5F00D` default exists in the **CLI's** argument parsing only.

---

## 6. Determinism

Same `(key, seed)` → byte-identical tables, bytecode, opcode maps and `fw_root`.
Same `(key, seed, pass, tier)` → a blob differing **only** in salt, nonce and
ciphertext/tag. This reproducibility is intentional and `tests/test_sdk.cpp`
depends on it.

The two committed blobs demonstrate it directly. `sealed.blob` (tier `high`) and
`sealed-light.blob` (tier `none`) were sealed from the same key and seed at
different tiers, and their `fw_root`, `code_len` and code bytes are identical —
which also confirms the tier changes *only* the KDF cost, never the white-box.

`tests/test_e2e.cpp` covers the other half: sealing the same program twice yields
different bytes of the same length, and both unseal to an identical table bank.

---

## 7. The SDK equivalent

```c
wbc_status wbc_seal_key(const uint8_t key[16], const char* passphrase,
                        uint64_t seed, int hardened, wbc_kdf_tier tier,
                        uint8_t** out_blob, size_t* out_len);
```

Same four stages, with these differences from the CLI:

* `hardened == 0` selects `ObfOptions::None()` — bare bytecode. The CLI has no
  such switch (§2).
* The tier is validated with `IsValidTier` *before* it can reach `Seal`: a blob
  is sealed once and opened forever, so a bogus tier must not be persistable.
* Returns a `malloc`'d buffer; free it with `wbc_free`, not `free`.
* A `noexcept` boundary: `std::bad_alloc` (an Argon2id arena failure) becomes
  `WBC_ERR_NOMEM`, anything else `WBC_ERR_ARG`.

**Build-time split, and it matters.** `wbc_seal_key` lives in its own
translation unit because it pulls in the reference AES, the white-box generator
and the assembler. It must **never** link into the shipped runtime library —
that would put the reference cipher and the table generator on the attacker's
device. See [BUILD.md](../BUILD.md) (runtime vs provisioning source sets); the
build asserts the runtime archive does not define this symbol.

---

## 8. The other end — opening the blob

`wbc_open` (`src/sdk/wbcrypto.cpp:73`) → `storage::Unseal`
(`src/storage/trusted_storage.cpp:217`), reading the caller's buffer directly
rather than copying ~455 KB:

1. Magic check.
2. **Exact** version match. A v3 blob is rejected, not reinterpreted: v4
   inserted `kdf_tier`, so a v3 blob's salt sits exactly where v4 reads the
   tier. There is deliberately no dual-read path — old blobs must be
   re-provisioned.
3. `IsValidTier` on the blob-supplied tier, *before* it can select a cost. The
   tier is a closed enum rather than raw ops/memory integers precisely so a blob
   cannot ask the runtime to allocate 4 GiB.
4. Bounds-checked field parse, then an **exactness** check:
   `header_len + data_len + 16 == blob_len`.
5. Derive the key at the blob's own tier and AEAD-decrypt the table bank.

A wrong passphrase, or any edit to the header, the opcode maps, the bytecode or
the ciphertext, fails the tag: `Unseal` returns `false` and `wbc_open` returns
`WBC_ERR_FORMAT`. **The blob does not open to a wrong-output program.**

After that, `wbc_encrypt_block` → `vm::Run`, which recomputes
`eff_root = fw_root ^ InterpFingerprint(op_to_phys)` and decodes each instruction
on fetch. `wbc_blob_kdf_tier` / `storage::PeekTier` reads the tier out of the
header for free — no passphrase, no KDF — so a deployed blob's cost is auditable
without paying to open it.

At the Argon2id tiers (`medium`/`heavy`) the KDF is ~96-99% of the cost, so `open`
is effectively independent of blob size. At `light` that is no longer true: the
KDF drops to ~1 ms and the loader's own work — header parse plus the 400 KB AEAD
decrypt — becomes the visible term. See [ARCHITECTURE §6.1](../ARCHITECTURE.md)
for the measured figures.

---

## 9. What the seal does and does not protect

**Does:** confidentiality of the table bank at rest, and tamper-evidence over the
*whole* program — header, both opcode maps, bytecode and tables — under one AEAD
tag. Fresh salt and nonce per seal, so identical inputs never produce identical
bytes and a nonce is never reused.

**Downgrade is not an attack.** `kdf_tier` sits inside the associated data, so
rewriting it to `light` changes both the derived key and the authenticated data;
the tag then fails for every passphrase. The attacker gets a cheap wrong answer,
not a cheap guessing oracle.

**Does not:** protect the key from someone running the field binary. In the
white-box threat model the attacker has the passphrase — it ships with, or inside,
the thing that opens the blob. The seal's role is to protect the blob **at rest**
and raise the offline-extraction bar; durable value needs hardware-backed key
binding, which is roadmap, not implemented.

**`--kdf light` has an entropy precondition that is yours to meet.**
HKDF-SHA256 is the *correct* construction for a ≥128-bit machine-generated
random passphrase, not a weakened one. But if a human can type the passphrase,
this tier is a full break of the seal's offline-guessing resistance. That is why
`heavy` is the default and `light` warns.

---

## 10. Provisioning-seed derivation

Stated plainly, because it bears directly on "is the key embedded or
randomized":

* `GenerateWhiteBox` does `Rng rng(seed)` (`src/wbaes/wb_generator.cpp:40`).
  Every internal `ByteEnc` therefore derives from the **provisioning seed alone**
  — the key is never mixed into the encoding RNG.
* `wb_keygen`'s default seed is the fixed constant `0xA5F00D`, and the shipped
  scripts use small literals (`42` in `gen_blob.sh`).
* The assembler seed is `seed ^ 0x9999` — correlated with the encoding seed, not
  independent of it.
* `op_to_phys`, a deterministic function of that assembler seed, sits in the
  **cleartext** associated data at offset 328.

Together these mean the seed is a security-relevant parameter, not a convenience
knob. **Pass a high-entropy `--seed` for anything you ship; never take the
default.**

Key-binding the encoding RNG (e.g. seeding from `H(key ‖ seed)`) and decoupling
the assembler seed are a known, deliberately deferred item — the change is
blob-format-incompatible and would need a v4→v5 bump plus re-provisioning of
every deployed blob.

---

## 11. Verifying a blob you just made

```sh
# Build the host tools and seal a demo key, with a built-in FIPS-197 self-check:
./scripts/gen_blob.sh

# Or by hand:
./build-host/wb_keygen --key 000102030405060708090a0b0c0d0e0f \
                       --pass demo --seed 42 --out wb.blob
./build-host/wb_encrypt --in wb.blob --pass demo \
                        --pt 00112233445566778899aabbccddeeff
# expect: 69c4e0d86a7b0430d8cdb78070b4c55a
```

Relevant suites: `test_e2e` (seal→unseal→run == AES, key absence, AEAD auth
failure on a flipped byte, salt uniqueness), `test_fw` (version gate, byte-tamper
decode cascade, opcode-map tamper), `test_sdk` (all three tiers seal, self-report
and open to the same ciphertext).
