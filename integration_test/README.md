# integration_test — third-party field-app integration

This directory is a **standalone consumer** of the White-box Crypto VM SDK: it links only
the runtime library (`libwbcrypto`) and the public header (`include/wbcrypto.h`), then
opens the bundled `sealed.blob` and uses the sealed key — exactly what a shipped app does.

## Why it exists

The static assessment in [`docs/WBC_static_assessment.md`](../docs/WBC_static_assessment.md)
was given only three files: `libwbcrypto.so`, `sealed.blob`, `wbcrypto.h`. Those files
**cannot reveal the opening passphrase** — `wbc_open(blob, len, passphrase, ctx)` receives
it from the *caller*. So the review split into:

- **Case A** — passphrase embedded/weak → key recoverable.
- **Case B** — passphrase is a strong external secret absent from the files → not recoverable.

and defaulted to Case B ("cannot retrieve the key"). **This directory is the missing file
that decides the case.** It shows the passphrase living inside the integration
(`"demo"`, compiled in) — i.e. the real deployment is **Case A**.

## What the demo shows

`field_app.cpp`:

1. Reads `sealed.blob`.
2. `wbc_open` with the compiled-in passphrase → clears **Layer 1** (Argon2id +
   ChaCha20-Poly1305), decrypting the white-box table bank in memory.
3. Drives the white-box as an AES oracle with the **FIPS-197** known-answer vector and
   confirms it reproduces `69c4e0d8…c55a` → the sealed key is `000102…0f`.
4. CTR encrypt/decrypt round-trip.

### Honest note on "retrieving the key"

The runtime API never returns the 16 raw key bytes — it only *uses* the key. The known-answer
test above **confirms** the key because this blob was sealed with the public FIPS test key
(`scripts/gen_blob.sh` defaults: key `000102…0f`, pass `demo`, seed `42`). For an **unknown**
key you cannot get the bytes from oracle access alone (that would just be breaking AES);
you would run a **BGE-family white-box attack (~2²²–2³²)** on the *decrypted* tables. The
point is that this integration is what **decrypts those tables** — Layer 1, the entire basis
of the assessment's B/B+ grade, is gone the moment you own an app that opens the blob.

## Build & run

Use a `libwbcrypto` built **for your run target**.

```sh
cmake -S . -B build
cmake --build build
./build/field_app                 # opens the bundled sealed.blob with pass "demo"
# or:
./build/field_app sealed.blob demo
```

Point at a specific SDK / library location:

```sh
cmake -S . -B build -DWBC_LIB_DIR=/path/to/native/build -DWBC_INCLUDE_DIR=/path/to/include
```

> ⚠️ The `libwbcrypto.so` committed at `../build` is an **Android/aarch64 (bionic)** build
> and will not load on a desktop **glibc** host. Rebuild the SDK for your platform
> (`../build.sh` at the repo root) or set `WBC_LIB_DIR` to a native build. For Android,
> consume this through the NDK toolchain / Gradle `externalNativeBuild`.

Expected output (abridged):

```
wbc_open:       OK  (Layer 1 cleared — table bank decrypted in memory)
KAT:            MATCH — behaves as standard AES-128
>> Sealed AES-128 key confirmed: 000102030405060708090a0b0c0d0e0f
round-trip:     OK
```

## Files

| File | Purpose |
|------|---------|
| `field_app.cpp` | The field-app integration (opens blob, uses/confirms the key). |
| `CMakeLists.txt` | Links `libwbcrypto` + `wbcrypto.h`; stages the blob next to the binary. |
| `sealed.blob` | The sealed key bank (moved here from the repo root). |
