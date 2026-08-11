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

/* The session key this SDK wraps: 32 bytes, the size a modern stream cipher or
 * AEAD takes (ChaCha20, XChaCha20-Poly1305, AES-256). */
#define WBC_SESSION_KEY_BYTES 32
/* A wrapped session key on the wire: 16-byte IV || 32-byte wrapped key. */
#define WBC_WRAPPED_KEY_BYTES 48

/* ---- Seal KDF cost tier --------------------------------------------------
 *
 * Which key derivation the seal uses. Chosen when the blob is sealed and
 * recorded IN THE BLOB, so any runtime opens any blob and a deployed blob's
 * cost is auditable after the fact (see wbc_blob_kdf_tier).
 *
 * This is the ONLY dial on wbc_open's latency: ~99% of a WBC_KDF_HIGH open is
 * the Argon2id call. The tiers do NOT differ in white-box strength — the VM,
 * the encodings and the table bank are identical at every tier.
 *
 * Argon2id exists to make each passphrase GUESS expensive. Pick the tier by
 * asking whether an attacker has to guess:
 *
 *   WBC_KDF_HIGH   a human chose the passphrase and it does NOT ship with the
 *                  blob. Guessing is the attack; pay to stop it.
 *   WBC_KDF_LOW    moderate-entropy secret, or you want a cost bump without a
 *                  64 MiB transient allocation at startup.
 *   WBC_KDF_NONE   the passphrase is a high-entropy machine secret. Nothing is
 *                  guessed, so a memory-hard KDF buys nothing for its cost.
 *
 * WBC_KDF_NONE IS SOUND ONLY IF the passphrase carries >= 128 bits of
 * uniformly random machine-generated entropy. If a human can type it, or it is
 * derived from anything guessable, this tier is a FULL BREAK of the seal's
 * offline-guessing resistance. It is the correct construction for a random
 * secret, not a weakened one — but the entropy precondition is yours to meet.
 *
 * Downgrade is not an attack: the tier is inside the AEAD's associated data,
 * so rewriting it changes both the derived key and the authenticated data, and
 * the tag then fails for every passphrase. */
typedef enum wbc_kdf_tier {
    WBC_KDF_NONE = 0,  /* HKDF-SHA256; microseconds                    */
    WBC_KDF_LOW  = 1,  /* Argon2id, 16 MiB / 2 passes                  */
    WBC_KDF_HIGH = 2   /* Argon2id, 64 MiB / 2 passes (libsodium
                        * INTERACTIVE) — the pre-3.0.0 behaviour       */
} wbc_kdf_tier;

typedef enum wbc_status {
    WBC_OK         =  0,
    WBC_ERR_ARG    = -1,  /* NULL/invalid argument or bad length          */
    WBC_ERR_FORMAT = -2,  /* malformed / truncated blob                   */
    WBC_ERR_NOMEM  = -3,  /* allocation failed                            */
    WBC_ERR_AUTH   = -4   /* AEAD authentication failed. NOT CURRENTLY
                           * RETURNED by any entry point: the seal's own tag
                           * failure surfaces as WBC_ERR_FORMAT from
                           * wbc_open, and the AEAD bulk helpers that used to
                           * return this are gone. The value is retained so
                           * the numbering stays stable for callers that
                           * switch on it; handle it, do not expect it.      */
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
 * `tier` selects the KDF cost paid by every later wbc_open of this blob --
 * read the wbc_kdf_tier contract above before choosing anything but
 * WBC_KDF_HIGH. Returns WBC_ERR_ARG for an out-of-range tier.
 * On success, *out_blob points to a malloc'd buffer (free it with wbc_free)
 * and *out_len holds its length. */
WBC_API wbc_status wbc_seal_key(const uint8_t key[WBC_KEY_BYTES],
                                const char* passphrase,
                                uint64_t seed,
                                int hardened,
                                wbc_kdf_tier tier,
                                uint8_t** out_blob,
                                size_t* out_len);

/* ---- Runtime: open a blob and encrypt ------------------------------------ */
/* Open a sealed blob (as produced by wbc_seal_key or the wb_keygen CLI).
 * The blob is authenticated (AEAD): a wrong passphrase or a tampered blob
 * returns WBC_ERR_FORMAT rather than opening. Free with wbc_close.
 *
 * Cost is dominated by the blob's own KDF tier, not by its size: a
 * WBC_KDF_HIGH blob takes ~250 ms on a phone whether its payload is 500 bytes
 * or 5 MB. Use wbc_blob_kdf_tier to find out which you have. */
WBC_API wbc_status wbc_open(const uint8_t* blob, size_t blob_len,
                            const char* passphrase, wbc_ctx** out_ctx);

/* Report the KDF tier a blob was sealed at, without opening it -- a header
 * read, so it costs nothing and needs no passphrase. Use it to audit what a
 * deployed blob actually paid for, or to enforce a minimum tier before
 * spending the open. Returns WBC_ERR_FORMAT if the blob is truncated, not a
 * WBTS blob, the wrong format version, or carries an unknown tier. */
WBC_API wbc_status wbc_blob_kdf_tier(const uint8_t* blob, size_t blob_len,
                                     wbc_kdf_tier* out_tier);

/* Encrypt exactly one 16-byte block.
 *
 * DIAGNOSTIC / KNOWN-ANSWER USE ONLY -- this is not a data path. It exists so a
 * caller can confirm the blob really holds the key they think it does, by
 * checking the FIPS-197 vector (key 000102..0f, plaintext 00112233..ff ->
 * 69c4e0d86a7b0430d8cdb78070b4c55a). Do NOT loop it over a payload: the VM runs
 * at well under 1 MB/s, so a megabyte takes minutes. Use the key-wrapping API
 * below for anything that is actually data. `in` and `out` may alias. */
WBC_API wbc_status wbc_encrypt_block(wbc_ctx* ctx,
                                     const uint8_t in[WBC_BLOCK_BYTES],
                                     uint8_t out[WBC_BLOCK_BYTES]);

/* ---- The one road: wrap a key with the white-box, move the data yourself ---
 *
 * THE WHITE-BOX IS SLOW ON PURPOSE: every 16-byte block is thousands of
 * obfuscated VM instructions, so it runs at well under 1 MB/s. The slowness IS
 * the obfuscation -- it cannot be optimized away without deleting the
 * protection. So the SDK deliberately offers NO way to push bulk data through
 * it, and no bulk cipher of its own: it protects a *key*, and YOU move the
 * *data* with a conventional cipher of your choosing.
 *
 *   uint8_t sk[WBC_SESSION_KEY_BYTES], wrapped[WBC_WRAPPED_KEY_BYTES];
 *   wbc_random(sk, sizeof sk);        // fresh session key
 *   wbc_wrap_key(ctx, sk, wrapped);   // white-box wraps it (2 blocks)
 *   your_cipher_encrypt(sk, data, n); // ChaCha20 / AES-CTR / an AEAD -- yours
 *   wbc_wipe(sk, sizeof sk);          // drop the plaintext key
 *
 * Store `wrapped` next to the payload. To read it back:
 *
 *   wbc_unwrap_key(ctx, wrapped, sk);
 *   your_cipher_decrypt(sk, in, in_len);
 *   wbc_wipe(sk, sizeof sk);
 *
 * `sk` is 32 bytes, so it drops straight into ChaCha20, XChaCha20-Poly1305 or
 * AES-256 without further derivation. The worked example is the ChaCha20 mirror
 * in native-lib-encryption's stub/stub_cipher.h, which decrypts a library's
 * .text with exactly this shape.
 *
 * The white-box cost is FIXED at two blocks per wrap -- it does not grow with
 * the payload, so only your cipher scales. A 5 MiB round trip is ~13 ms per leg
 * this way, against ~85 s if the payload itself went through the VM.
 *
 * WHAT THIS DOES AND DOES NOT PROTECT. The white-box protects the LONG-TERM key
 * -- that key is never reconstructed in memory. It does NOT extend that
 * guarantee to the session key or the bulk data: between the unwrap and the
 * wbc_wipe, `sk` is an ordinary key in ordinary memory, and an attacker who can
 * dump the process gets it without attacking the white-box at all. This is a
 * deliberate trade of white-box coverage for throughput. Keep the plaintext
 * session key's lifetime as short as you can, prefer a fresh key per message
 * over a long-lived one, and always wbc_wipe it.
 */

/* Wrap a session key with the white-box. `wrapped` receives IV || ciphertext.
 *
 * The IV is generated internally and prepended, so it cannot be reused: CTR
 * with a repeated IV under the same long-term key would leak the XOR of two
 * session keys, and making the caller supply it made that an easy mistake.
 * Wrapping the same key twice therefore yields different bytes, by design.
 *
 * The wrap is NOT separately authenticated, and deliberately so. A corrupted
 * `wrapped` simply unwraps to a DIFFERENT session key -- wbc_unwrap_key still
 * returns WBC_OK, because CTR has nothing to check. Detecting that is your
 * cipher's job: an AEAD fails its tag, and a bare stream cipher yields garbage
 * plaintext you must be able to recognise. If your data path has no integrity
 * check of its own, add one; do not read WBC_OK from wbc_unwrap_key as evidence
 * that `wrapped` arrived intact. */
WBC_API wbc_status wbc_wrap_key(wbc_ctx* ctx,
                                const uint8_t session_key[WBC_SESSION_KEY_BYTES],
                                uint8_t wrapped[WBC_WRAPPED_KEY_BYTES]);

/* Recover a session key produced by wbc_wrap_key. Returns WBC_OK for any
 * well-formed input -- see the authentication note above. */
WBC_API wbc_status wbc_unwrap_key(wbc_ctx* ctx,
                                  const uint8_t wrapped[WBC_WRAPPED_KEY_BYTES],
                                  uint8_t session_key[WBC_SESSION_KEY_BYTES]);

/* Fill `buf` with cryptographically secure random bytes. */
WBC_API wbc_status wbc_random(uint8_t* buf, size_t len);

/* Best-effort erase of sensitive memory; not optimized away by the compiler. */
WBC_API void wbc_wipe(void* p, size_t len);

/* Release a context. */
WBC_API void wbc_close(wbc_ctx* ctx);

/* Free a buffer returned by the SDK (e.g. wbc_seal_key's out_blob). */
WBC_API void wbc_free(void* p);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WBCRYPTO_H */
