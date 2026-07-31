# Android hardening (anti-tamper, anti-DBI, device binding)

> **Status: `[unverified-here]` code-drops.** The modules described here are
> written and compile, but they are **not wired into the host-verified build**
> and have **not been validated on a device**. They target the Android/NDK build
> and must be integrated and tested there. Every technique below is individually
> bypassable — the value is in *combining many cheap checks with the O-MVLL
> obfuscation* so removal is tedious, never in any single check.

This is the layer the threat model calls out as the **dominant real threat**
(dynamic extraction from a running process) and the **highest-value durable
item** (hardware-backed binding). Obfuscation and anti-tamper multiply an
existing floor; they do not create one — land the crypto/structure work first
(seal, runtime/provisioning split), which is already done.

## 1. Native-code obfuscation — O-MVLL (P2.1)

`obfuscation/omvll_config.py` targets the sensitive **functions** (never whole
modules — that overwhelms the backend; see the file's header) in the hot TUs:
`vm.cpp`, `handlers.cpp`, `assembler.cpp`, `trusted_storage.cpp`, `fwcrypt.cpp`,
the SDK glue, and the freestanding stub. Enabled passes:

- control-flow flattening + bogus control flow (everywhere sensitive),
- opaque/encrypted **constants** and **string encoding** on the shipped,
  non-freestanding TUs — this is what removes the `WBTS` magic and the
  SplitMix64/FNV constants from a `strings`/constant scan,
- MBA arithmetic (heaviest — bring up last; dial back if the register coalescer
  crashes),
- anti-hooking on the runtime/SDK TUs.

Build via the NDK cross-compile in [BUILD.md](BUILD.md) (Option C). Benchmark
`wbc_encrypt_block` after enabling CFF/MBA and pick a level you can afford.

## 2. Anti-DBI / anti-tamper — `src/rt/anti_tamper.*` (P3)

Layered checks with **no single choke point**, that **degrade silently**:

- `DetectInstrumentation()` — `/proc/self/status` TracerPid, `/proc/self/maps`
  scan for frida/gum/gadget, `PTRACE_TRACEME` self-attach, and a hot-path timing
  probe. Returns an OR of flags; spread calls around and combine results.
- `TextChecksum(start, len)` — FNV-1a over a critical `.text` span for a runtime
  self-integrity check (compare against a hash baked in at build time).
- `DegradationMask(text_start, text_len, expected_hash)` — folds the above into
  a value that is **0 when clean** and non-zero otherwise.

**Integration rule:** do *not* branch on these. Mix `DegradationMask(...)` into
the seal/KDF key material (e.g. XOR into the passphrase-derived input, or into
the CTR counter/table pointers) so a hooked or patched process silently derives
the **wrong key** and produces wrong ciphertext — never a clean boolean an
attacker can NOP out at one site. Scatter the mixing across the hot path and let
O-MVLL obfuscate it.

Tuning: the timing threshold is generous to avoid false positives on cold/slow
devices; measure on your target hardware. `ptrace` may be unavailable in some
sandboxes — treat that signal as corroborating, not decisive.

## 3. Hardware-backed device binding — `src/rt/device_binding.*` (P2.4)

The seal on its own protects the blob at rest, but an attacker who runs the field
binary has the passphrase. Binding the seal key to the **Android Keystore /
StrongBox** turns "steal the file + passphrase" into "defeat the secure element":

1. At provisioning, generate a random 32-byte device secret; store it as a
   **non-exportable** Keystore key (StrongBox if present) and mix it into the
   seal KDF input.
2. At runtime, `DeviceKeyMaterial(alias, out)` asks the Keystore (via a JNI
   bridge, not included) to reproduce/unwrap that material — it never leaves the
   secure element in the clear — and the runtime mixes it into the KDF.

A blob provisioned for device A then fails to open on device B (different
Keystore material → different AEAD key). This requires a new `wbc_open` variant
that accepts extra key material; the current C ABI is intentionally left raw
until the JNI bridge and on-device validation exist. `DeviceKeyMaterial` is a
stub returning `false` (passphrase-only fallback) until then.

## Acceptance (run on the NDK + device build)

- `strings libwbcrypto.so` reveals neither `WBTS` nor the PRNG/FNV constants.
- A Frida hook of the white-box path triggers degradation (wrong output), not a
  clean dump.
- Patching a byte in `.text` yields wrong ciphertext (integrity mixing active).
- A blob provisioned on device A does not open on device B.
- `wbc_encrypt_block` throughput stays within budget after CFF/MBA.
