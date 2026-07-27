# Integrating with `native-lib-encryption`

Target: **github.com/lambertse/native-lib-encryption** — a Python APK packer
(`sopack/`) that encrypts Android `.so` libraries at rest and decrypts them at
load time with a freestanding C **stub** (`stub/stub.c`, `stub/stub_cipher.h`).

## Why this SDK is relevant

`native-lib-encryption`'s own caveat:

> "…provides obfuscation only — **the decryption key ships inside the binary**,
> and plaintext exists in a readable mapping at runtime."

That is exactly the problem a white-box addresses: with this SDK the payload key
is **diffused across lookup tables**, never present as raw bytes. The integration
replaces (or adds) a cipher whose key is not recoverable by a static scan of the
packed APK.

## The two boundaries and a hard constraint

`native-lib-encryption` has two sides with very different runtimes:

| Side | Where | Runtime | Can it use `libwbcrypto`? |
|------|-------|---------|---------------------------|
| Packer | `sopack/cipher.py` (host, pack time) | full Python/libc | **Yes** — via ctypes |
| Stub | `stub/stub_cipher.h` (device, load time) | **freestanding, no libc/malloc** | **No** — `wbc_ctx` needs libc + the C++ runtime |

Their payload cipher is **ChaCha20/XOR**, implemented twice (Python + stub C).
This SDK is **white-box AES-128-CTR**. Genuine integration therefore means
switching the payload cipher to WB-AES-CTR on both sides — you cannot "white-box"
a raw ChaCha20 key and still feed it to ChaCha20 (the key would reappear).

## Path A — host / packer side (buildable today)

Use `libwbcrypto.so` from `sopack` to encrypt each library payload with
white-box AES-CTR at pack time, and ship the sealed blob instead of a raw key.

```python
# sopack/wbcipher.py  (sketch — drop-in alongside cipher.py)
import ctypes, os
lib = ctypes.CDLL("build/libwbcrypto.so")
lib.wbc_seal_key.restype = ctypes.c_int
lib.wbc_open.restype = ctypes.c_int
lib.wbc_crypt_ctr.restype = ctypes.c_int

def seal(key16: bytes, passphrase: bytes, hardened=1) -> bytes:
    out = ctypes.POINTER(ctypes.c_ubyte)(); n = ctypes.c_size_t()
    lib.wbc_seal_key(key16, passphrase, ctypes.c_uint64(0), hardened,
                     ctypes.byref(out), ctypes.byref(n))
    blob = bytes(ctypes.cast(out, ctypes.POINTER(ctypes.c_ubyte * n.value)).contents)
    lib.wbc_free(out); return blob

def ctr(blob: bytes, passphrase: bytes, iv16: bytes, data: bytes) -> bytes:
    ctx = ctypes.c_void_p()
    lib.wbc_open(blob, len(blob), passphrase, ctypes.byref(ctx))
    out = (ctypes.c_ubyte * len(data))()
    lib.wbc_crypt_ctr(ctx, iv16, data, out, len(data))
    lib.wbc_close(ctx); return bytes(out)
```

Then in the packing flow: `blob = seal(key, pass)`, encrypt the `.so` with
`ctr(blob, pass, iv, so_bytes)`, and store the **blob** (not the key) in the
injected `decinfo` segment. This hides the key at pack time and in the shipped
artifact.

> Note: Path A alone still needs *something* on device to decrypt. If that
> decryptor holds the raw key, you have not improved on their status quo — the
> win only materializes when the on-device decryptor is itself the white-box,
> i.e. Path B.

## Path B — runtime / stub side (the piece that fixes their caveat)

**This is now implemented in this repo** as a freestanding, no-libc, no-malloc,
relocation-free (no function pointers) white-box runtime, ready to drop into the
stub. Two files, both pure C:

| File | Role |
|------|------|
| `freestanding/wb_stub.h`         | header-only runtime: `wbstub_encrypt_block`, `wbstub_ctr_xcrypt` |
| `freestanding/wb_table_layout.h` | the flat table-image layout (shared with the exporter) |

The device runs the **table network directly** — no VM bytecode/dispatcher (that
needs mutable memory). The security property carried onto the device is that the
AES key is diffused across these tables and never appears as raw bytes.

### 1. Export the table image at pack time

```sh
# 409612-byte image: 12-byte header + T-box/Tyi/XOR bank
./build/wb_keygen --key <32 hex> --seed 12345 --export-tables libfoo.wbt
```
or from Python via the SDK: `wbc_export_tables(key, seed, &img, &len)`.

Inject `libfoo.wbt` into the packed APK the same way the current `decinfo`
payload is carried (pointer + length in the 128-byte protocol). Remember the
`seed` — the runtime needs the matching image, but *not* the key.

### 2. Use it in the stub

In `stub/stub_cipher.h`, replace the ChaCha20 call with:

```c
#include "wb_stub.h"   /* copy freestanding/wb_stub.h + wb_table_layout.h into stub/ */

/* `tables` points at the injected image; decrypt the mapped payload in place */
wbstub_ctr_xcrypt(tables, iv /*16*/, payload, payload, payload_len);
```

`wbstub_ctr_xcrypt` encrypts and decrypts with the same call (CTR), so it is a
direct swap for the existing stream-cipher step.

### 3. Build flags

The runtime compiles under the stub's freestanding toolchain; the repo's build
gate proves it emits no libc calls:

```sh
$(NDK)/clang --target=aarch64-linux-android21 \
    -ffreestanding -fno-builtin -fno-stack-protector -nostdlib -fPIC \
    -Istub -c stub.c -o stub.o          # wb_stub.h included from stub_cipher.h
```

Trade-off to note: the ~400 KB table image is larger than a 32-byte ChaCha20
key, and the on-device code no longer carries the VM-bytecode obfuscation (only
the host/SDK path does). What the device gains is that **no raw key exists in the
APK** — extraction now requires cryptanalysis of the tables, not a byte scan.

## End-to-end recipe

1. **Pack time (host):** `wb_keygen --key … --export-tables lib.wbt` (or
   `wbc_export_tables` via ctypes). Encrypt each `.so` with WB-AES-CTR — either
   with `wbstub_ctr_xcrypt` compiled for the host, or `wbc_crypt_ctr` from
   `libwbcrypto`. Inject `lib.wbt` via the existing `decinfo` channel.
2. **Load time (device):** the stub calls `wbstub_ctr_xcrypt(tables, iv, buf,
   buf, len)` to decrypt in place. No raw key is present anywhere in the APK.

Both sides use the *same* table image and the *same* CTR routine, so they are
guaranteed to agree (the repo differential-tests `wb_stub.h` against the C++
interpreter and AES).

### What the device path does and does not get

The device runs the **table network directly** (`wb_stub.h`). It therefore does
**not** carry the host-side VM layers — virtualization, opcode blinding, MBA,
opaque predicates, and the **context-keyed firmware / runtime anti-tamper**
(`src/fw/`). Those harden the *host/SDK/CLI VM path* only. On device the property
you gain is **key diffusion** (no raw key in the APK); static hardening of the
on-device code remains the packer's own concern (its existing ELF encryption).

Honest scope: this is not unbreakable — Chow's white-box is academically
extractable. It raises the bar from "grep the APK for the key" to "run a
cryptanalytic attack on the tables", a large practical improvement for a packer.
The image is ~400 KB vs a 32-byte key. See **[THREATMODEL.md](THREATMODEL.md)**
for the full layer-by-layer analysis and attacker model.
