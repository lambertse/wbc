# SDK Guide (C ABI: `libwbcrypto`)

The White-box Crypto VM ships as a **static** (`libwbcrypto.a`) and **shared**
(`libwbcrypto.so`) library with a stable C header (`include/wbcrypto.h`). Any
native project — C/C++, Android NDK/JNI, or Rust/Go/Swift/Python via FFI — can
link it. The CLI tools remain available; the library is additive.

> Read **[THREATMODEL.md](THREATMODEL.md)** before relying on this for anything
> security-sensitive. In short: it hides the key from a *static* scan and makes
> the blob tamper-evident, but it is not key secrecy against a cryptanalyst and
> not resistance against an attacker who can run/trace the code. Treat sealed
> blobs as integrity-chained — do not edit them; any change yields wrong output.

## What you get

| Artifact                 | Path                    |
|--------------------------|-------------------------|
| Public header            | `include/wbcrypto.h`    |
| Static library           | `build/libwbcrypto.a`   |
| Shared library           | `build/libwbcrypto.so`  |
| C integration example    | `examples/example.c`    |

Build them with `./build.sh` (see [BUILD.md](BUILD.md)); the libraries and the
example are produced automatically alongside the tools and tests.

## The API in one glance

```c
#include "wbcrypto.h"

const char* wbc_version(void);
const char* wbc_strerror(wbc_status);

/* offline / PROVISIONING ONLY (libwbprovision, NOT the shipped runtime):
 * seal a 16-byte key into a trusted-storage blob (malloc'd out_blob) */
wbc_status wbc_seal_key(const uint8_t key[16], const char* passphrase,
                        uint64_t seed, int hardened,
                        uint8_t** out_blob, size_t* out_len);

/* offline / PROVISIONING ONLY: export a flat table image for the freestanding
 * device runtime (see INTEGRATION-native-lib-encryption.md); malloc'd */
wbc_status wbc_export_tables(const uint8_t key[16], uint64_t seed,
                             uint8_t** out_image, size_t* out_len);

/* runtime (shipped in libwbcrypto). wbc_open AUTHENTICATES the blob: a wrong
 * passphrase or any tamper returns WBC_ERR_FORMAT rather than opening. */
wbc_status wbc_open(const uint8_t* blob, size_t len, const char* passphrase, wbc_ctx** out);
wbc_status wbc_encrypt_block(wbc_ctx*, const uint8_t in[16], uint8_t out[16]); /* ECB, 1 block */
wbc_status wbc_encrypt_ecb  (wbc_ctx*, const uint8_t* in, uint8_t* out, size_t len); /* len %16==0 */
wbc_status wbc_crypt_ctr    (wbc_ctx*, const uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t len);
void       wbc_close(wbc_ctx*);
void       wbc_free(void* blob);
```

`in`/`out` may alias. All functions are noexcept and return a `wbc_status`
(`WBC_OK`, `WBC_ERR_ARG`, `WBC_ERR_FORMAT`, `WBC_ERR_NOMEM`).

**CTR gives you decryption.** The white-box only *encrypts* blocks, but
`wbc_crypt_ctr` uses block-encryption as a keystream generator, so the *same
call* encrypts and decrypts arbitrary-length data — this is the mode to use for
real payloads. ECB is exposed mainly as the raw primitive / for KATs.

**Thread-safety:** a `wbc_ctx` is not thread-safe (each call mutates a private
VM data image). Use one context per thread or serialize access.

## Linking

Shared:
```sh
cc app.c -Iinclude -Lbuild -lwbcrypto -Wl,-rpath,'$ORIGIN' -o app
```
Static (no runtime dependency; note it pulls in the C++ runtime, so link with a
C++ driver or add `-lstdc++`):
```sh
c++ app.c -Iinclude build/libwbcrypto.a -o app          # or:
cc  app.c -Iinclude -DWBC_STATIC build/libwbcrypto.a -lstdc++ -o app
```
Define `-DWBC_STATIC` when using the static archive so the header does not mark
symbols as `dllimport` on Windows.

## Typical flow

```c
uint8_t* blob; size_t n;
wbc_seal_key(key, "pass", 42, /*hardened=*/1, &blob, &n);   // once, offline
/* ship `blob` with your app; the key is diffused inside it */

wbc_ctx* c;
wbc_open(blob, n, "pass", &c);                              // at startup
uint8_t iv[16] = {0};
wbc_crypt_ctr(c, iv, payload, out, payload_len);            // encrypt / decrypt
wbc_close(c);
wbc_free(blob);
```

## FFI notes

- **Python (ctypes):** load `libwbcrypto.so`, declare the prototypes, pass
  `bytes`/`ctypes.create_string_buffer`. Free `out_blob` with `wbc_free`.
- **Android NDK/JNI:** add `libwbcrypto` to your `CMakeLists.txt`
  (`target_link_libraries`), call the C functions from your JNI bridge; no JNI
  glue lives in the library itself, so it stays portable.
- **Rust:** `bindgen` the header or hand-declare the `extern "C"` block; wrap the
  `wbc_ctx*` in an owning type whose `Drop` calls `wbc_close`.

> A `wbc_ctx` needs libc/malloc and the C++ runtime. It is **not** usable from a
> freestanding / no-libc environment (e.g. a raw ELF loader stub). For that, see
> [INTEGRATION-native-lib-encryption.md](INTEGRATION-native-lib-encryption.md).
