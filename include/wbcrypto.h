/* wbcrypto.h — C ABI for the White-box Crypto VM SDK.
 *
 * A stable, language-agnostic surface for embedding the obfuscated white-box
 * AES-128 VM into a native project (C/C++, Android NDK/JNI, Rust/Go/Swift via
 * FFI, ...). The AES key is sealed offline into a trusted-storage blob; at
 * runtime you open the blob and encrypt blocks — the key is never reconstructed.
 *
 * Threat model & limitations: see README.md. This raises the bar against static
 * analysis; it is not an unbreakable key vault.
 *
 * Thread-safety: a wbc_ctx is NOT thread-safe (each encrypt call mutates a
 * private VM data image). Use one context per thread, or serialize access.
 */
#ifndef WBCRYPTO_H
#define WBCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Symbol visibility (define WBC_STATIC when linking the static archive). */
#if defined(_WIN32) && !defined(WBC_STATIC)
#  ifdef WBC_BUILD
#    define WBC_API __declspec(dllexport)
#  else
#    define WBC_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) && !defined(WBC_STATIC)
#  define WBC_API __attribute__((visibility("default")))
#else
#  define WBC_API
#endif

#define WBC_KEY_BYTES   16
#define WBC_BLOCK_BYTES 16

/* Session key for the bulk helpers below (XChaCha20-Poly1305). */
#define WBC_SESSION_KEY_BYTES 32
/* Bytes wbc_bulk_seal adds to the plaintext: 24-byte nonce + 16-byte tag. */
#define WBC_BULK_OVERHEAD 40

typedef enum wbc_status {
    WBC_OK         =  0,
    WBC_ERR_ARG    = -1,  /* NULL/invalid argument or bad length          */
    WBC_ERR_FORMAT = -2,  /* malformed / truncated blob                   */
    WBC_ERR_NOMEM  = -3,  /* allocation failed                            */
    WBC_ERR_AUTH   = -4   /* AEAD authentication failed (wrong key, or
                           * the ciphertext was modified)                 */
} wbc_status;

/* Opaque handle around a loaded, sealed white-box program. */
typedef struct wbc_ctx wbc_ctx;

/* Library version string, e.g. "1.0.0". */
WBC_API const char* wbc_version(void);

/* Human-readable name for a status code (never NULL). */
WBC_API const char* wbc_strerror(wbc_status s);

/* ---- Offline: seal a key into a trusted-storage blob --------------------- */
/* Seal a 16-byte AES-128 key. `passphrase` may be NULL (treated as empty).
 * `seed` diversifies the encodings/obfuscation (pass 0 for a default).
 * `hardened` != 0 applies full bytecode obfuscation; 0 emits bare bytecode.
 * On success, *out_blob points to a malloc'd buffer (free it with wbc_free)
 * and *out_len holds its length. */
WBC_API wbc_status wbc_seal_key(const uint8_t key[WBC_KEY_BYTES],
                                const char* passphrase,
                                uint64_t seed,
                                int hardened,
                                uint8_t** out_blob,
                                size_t* out_len);

/* ---- Runtime: open a blob and encrypt ------------------------------------ */
/* Open a sealed blob (as produced by wbc_seal_key or the wb_keygen CLI).
 * The blob is authenticated (AEAD): a wrong passphrase or a tampered blob
 * returns WBC_ERR_FORMAT rather than opening. Free with wbc_close. */
WBC_API wbc_status wbc_open(const uint8_t* blob, size_t blob_len,
                            const char* passphrase, wbc_ctx** out_ctx);

/* Encrypt exactly one 16-byte block (ECB). `in` and `out` may alias. */
WBC_API wbc_status wbc_encrypt_block(wbc_ctx* ctx,
                                     const uint8_t in[WBC_BLOCK_BYTES],
                                     uint8_t out[WBC_BLOCK_BYTES]);

/* Encrypt `len` bytes in ECB mode; `len` must be a multiple of 16.
 * `in` and `out` may alias (identical pointers). */
WBC_API wbc_status wbc_encrypt_ecb(wbc_ctx* ctx, const uint8_t* in,
                                   uint8_t* out, size_t len);

/* CTR mode over the white-box block cipher: the SAME call encrypts and
 * decrypts. Handles arbitrary `len` (no padding). `iv` is the initial 16-byte
 * counter (incremented big-endian per block). Because CTR only ever needs the
 * block-ENCRYPT primitive, this gives you decryption too, even though the
 * white-box itself only encrypts. `in`/`out` may alias. */
WBC_API wbc_status wbc_crypt_ctr(wbc_ctx* ctx, const uint8_t iv[WBC_BLOCK_BYTES],
                                 const uint8_t* in, uint8_t* out, size_t len);

/* ---- Bulk data: key wrapping ---------------------------------------------
 *
 * THE WHITE-BOX IS SLOW ON PURPOSE. It runs well under 1 MB/s (budget ~25 s per
 * MiB per leg), because every 16-byte block is ~13k obfuscated VM instructions.
 * Pushing megabytes through wbc_crypt_ctr is therefore the wrong shape. The
 * right shape is to protect a *key* with the white-box and move the *data* with
 * a conventional cipher:
 *
 *   wbc_random(sk, WBC_SESSION_KEY_BYTES);        // fresh session key
 *   wbc_crypt_ctr(ctx, iv, sk, wrapped, 32);      // white-box wraps it (2 blocks)
 *   wbc_bulk_seal(sk, data, n, out, &out_n);      // conventional AEAD moves data
 *   wbc_wipe(sk, sizeof sk);                      // drop the plaintext key
 *
 * Store `wrapped` alongside the ciphertext. To read it back, unwrap with the
 * same wbc_crypt_ctr call (CTR is its own inverse) and wbc_bulk_open.
 *
 * WHAT THIS DOES AND DOES NOT PROTECT. The white-box protects the LONG-TERM key
 * -- that key is never reconstructed in memory. It does NOT extend that
 * guarantee to the session key or the bulk data: between wbc_crypt_ctr and
 * wbc_wipe, `sk` is an ordinary key in ordinary memory, and an attacker who can
 * dump the process gets it without attacking the white-box at all. This is a
 * deliberate trade of white-box coverage for throughput. Keep the plaintext
 * session key's lifetime as short as you can, prefer a fresh key per message
 * over a long-lived one, and always wbc_wipe it.
 */

/* Fill `buf` with cryptographically secure random bytes. */
WBC_API wbc_status wbc_random(uint8_t* buf, size_t len);

/* Best-effort erase of sensitive memory; not optimized away by the compiler. */
WBC_API void wbc_wipe(void* p, size_t len);

/* Encrypt+authenticate `len` bytes under a session key (XChaCha20-Poly1305).
 * `out` must have room for len + WBC_BULK_OVERHEAD bytes; the nonce is chosen
 * randomly and prepended, so callers never manage nonces. *out_len receives the
 * bytes written. `in` and `out` must NOT overlap. */
WBC_API wbc_status wbc_bulk_seal(const uint8_t key[WBC_SESSION_KEY_BYTES],
                                 const uint8_t* in, size_t len,
                                 uint8_t* out, size_t* out_len);

/* Inverse of wbc_bulk_seal. `len` is the sealed length (>= WBC_BULK_OVERHEAD);
 * `out` needs len - WBC_BULK_OVERHEAD bytes. Returns WBC_ERR_AUTH if the data
 * or key is wrong -- on failure nothing is written. `in`/`out` must NOT overlap. */
WBC_API wbc_status wbc_bulk_open(const uint8_t key[WBC_SESSION_KEY_BYTES],
                                 const uint8_t* in, size_t len,
                                 uint8_t* out, size_t* out_len);

/* Release a context. */
WBC_API void wbc_close(wbc_ctx* ctx);

/* Free a buffer returned by the SDK (e.g. wbc_seal_key's out_blob). */
WBC_API void wbc_free(void* p);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WBCRYPTO_H */
