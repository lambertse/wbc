// wbcrypto.cpp — C ABI RUNTIME implementation over the C++ white-box VM core.
//
// This translation unit is the one that SHIPS in libwbcrypto.{a,so}. It must
// contain only the field-side runtime: open a sealed blob and encrypt. The
// key-generation surface (wbc_seal_key, which pulls in the reference AES, the
// white-box generator, and the assembler) lives in the
// separate wbcrypto_provision.cpp so that code never ships alongside the thing
// that must not reveal the key. See docs/BUILD.md (runtime vs provisioning).
//
// All entry points are noexcept boundaries: C++ exceptions (e.g. bad_alloc) are
// caught and translated to wbc_status codes so they never cross into C callers.
#define WBC_BUILD
#include "wbcrypto.h"

#include <sodium.h>

#include <cstdlib>
#include <cstring>
#include <new>

#include "storage/trusted_storage.h"
#include "vm/vm.h"

struct wbc_ctx {
    vm::Program prog;
};

/* wbc_kdf_tier and storage::KdfTier are cast into each other in both directions
 * (wbc_blob_kdf_tier here, wbc_seal_key in wbcrypto_provision.cpp). They are
 * separate types because one is the C ABI and the other is internal; pin the
 * values so a future edit to either enum is a build error rather than a blob
 * silently sealed at the wrong cost. */
static_assert(static_cast<uint32_t>(storage::KdfTier::kNone) == WBC_KDF_NONE, "tier enum drift");
static_assert(static_cast<uint32_t>(storage::KdfTier::kLow) == WBC_KDF_LOW, "tier enum drift");
static_assert(static_cast<uint32_t>(storage::KdfTier::kHigh) == WBC_KDF_HIGH, "tier enum drift");

extern "C" {

/* 3.0.0: the seal KDF cost became a per-blob tier recorded in the header (blob
 * format v3 -> v4, no dual-read: v3 blobs must be re-provisioned) and
 * wbc_seal_key gained a `tier` parameter. The RUNTIME ABI is unchanged --
 * wbc_open and friends keep their signatures; the break is in the provisioning
 * surface, which never ships in this library.
 * 2.0.0: the bulk entry points (wbc_encrypt_ecb, wbc_crypt_ctr) were removed in
 * favour of wbc_wrap_key/wbc_unwrap_key. Breaking ABI change, hence the major. */
const char* wbc_version(void) { return "3.0.0"; }

const char* wbc_strerror(wbc_status s) {
    switch (s) {
        case WBC_OK: return "ok";
        case WBC_ERR_ARG: return "invalid argument";
        case WBC_ERR_FORMAT: return "malformed blob";
        case WBC_ERR_NOMEM: return "out of memory";
        case WBC_ERR_AUTH: return "authentication failed";
    }
    return "unknown";
}

/* wbc_seal_key is the key-generation surface; it lives in
 * wbcrypto_provision.cpp (provisioning build) and is deliberately NOT part of
 * the shipped runtime library. */

wbc_status wbc_open(const uint8_t* blob, size_t blob_len, const char* passphrase,
                    wbc_ctx** out_ctx) {
    if (!blob || !out_ctx) return WBC_ERR_ARG;
    try {
        auto* ctx = new wbc_ctx();
        std::string pass = passphrase ? passphrase : "";
        /* Unseal reads the caller's buffer directly. It used to be handed a
         * std::vector copy of the whole blob (~455 KB) purely to match a vector
         * parameter — invisible next to a 250 ms Argon2id, but a measurable
         * fraction of a WBC_KDF_NONE open. */
        if (!storage::Unseal(blob, blob_len, pass, ctx->prog)) {
            delete ctx;
            return WBC_ERR_FORMAT;
        }
        *out_ctx = ctx;
        return WBC_OK;
    } catch (const std::bad_alloc&) {
        return WBC_ERR_NOMEM;
    } catch (...) {
        return WBC_ERR_FORMAT;
    }
}

wbc_status wbc_blob_kdf_tier(const uint8_t* blob, size_t blob_len,
                             wbc_kdf_tier* out_tier) {
    if (!blob || !out_tier) return WBC_ERR_ARG;
    storage::KdfTier tier;
    if (!storage::PeekTier(blob, blob_len, tier)) return WBC_ERR_FORMAT;
    *out_tier = static_cast<wbc_kdf_tier>(tier);
    return WBC_OK;
}

wbc_status wbc_encrypt_block(wbc_ctx* ctx, const uint8_t in[WBC_BLOCK_BYTES],
                             uint8_t out[WBC_BLOCK_BYTES]) {
    if (!ctx || !in || !out) return WBC_ERR_ARG;
    try {
        std::array<uint8_t, 16> blk{};
        std::memcpy(blk.data(), in, 16);
        auto res = vm::Run(ctx->prog, blk);
        std::memcpy(out, res.data(), 16);
        return WBC_OK;
    } catch (...) {
        return WBC_ERR_NOMEM;
    }
}

/* ---- The one road: key wrapping ------------------------------------------
 *
 * There is deliberately no bulk-through-the-VM entry point. CTR over exactly
 * WBC_SESSION_KEY_BYTES is the ONLY use of the block cipher as a stream cipher,
 * and the length is a compile-time constant here rather than a caller argument,
 * so the "push a megabyte through the white-box" shape is not expressible.
 *
 * Shared by wrap and unwrap: CTR is its own inverse, so both directions are the
 * same keystream XOR. `iv` is the initial counter block.
 */
/* Sizes are checked against the libsodium constants with static_assert rather
 * than assumed, so a libsodium upgrade that changed them is a build error
 * instead of a buffer overflow. */
static_assert(WBC_SESSION_KEY_BYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
              "WBC_SESSION_KEY_BYTES must track libsodium's KEYBYTES");
static_assert(WBC_BULK_OVERHEAD == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                       crypto_aead_xchacha20poly1305_ietf_ABYTES,
              "WBC_BULK_OVERHEAD must track libsodium's NPUBBYTES + ABYTES");
static_assert(WBC_WRAPPED_KEY_BYTES == WBC_BLOCK_BYTES + WBC_SESSION_KEY_BYTES,
              "WBC_WRAPPED_KEY_BYTES is the IV plus the wrapped key");

namespace {
constexpr size_t kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24

/* sodium_init() is idempotent; <0 means the RNG is unusable. */
bool EnsureSodium() { return sodium_init() >= 0; }

void CtrSessionKey(const vm::Program& prog, const uint8_t iv[WBC_BLOCK_BYTES],
                   const uint8_t* in, uint8_t* out) {
    std::array<uint8_t, 16> counter{};
    std::memcpy(counter.data(), iv, 16);
    for (size_t off = 0; off < WBC_SESSION_KEY_BYTES; off += 16) {
        auto ks = vm::Run(prog, counter);  // keystream block = E(counter)
        size_t n = WBC_SESSION_KEY_BYTES - off;
        if (n > 16) n = 16;
        for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ ks[i];
        // big-endian 128-bit counter increment
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
        // The keystream is as sensitive as the key it hides; do not leave it on
        // the stack for a later dump to find.
        sodium_memzero(ks.data(), ks.size());
    }
    sodium_memzero(counter.data(), counter.size());
}
}  // namespace

wbc_status wbc_wrap_key(wbc_ctx* ctx, const uint8_t session_key[WBC_SESSION_KEY_BYTES],
                        uint8_t wrapped[WBC_WRAPPED_KEY_BYTES]) {
    if (!ctx || !session_key || !wrapped) return WBC_ERR_ARG;
    if (!EnsureSodium()) return WBC_ERR_NOMEM;
    try {
        /* Fresh IV per wrap, generated here so a caller cannot reuse one. It is
         * not secret; it travels in the clear ahead of the wrapped key. */
        randombytes_buf(wrapped, WBC_BLOCK_BYTES);
        CtrSessionKey(ctx->prog, wrapped, session_key, wrapped + WBC_BLOCK_BYTES);
        return WBC_OK;
    } catch (...) {
        return WBC_ERR_NOMEM;
    }
}

wbc_status wbc_unwrap_key(wbc_ctx* ctx, const uint8_t wrapped[WBC_WRAPPED_KEY_BYTES],
                          uint8_t session_key[WBC_SESSION_KEY_BYTES]) {
    if (!ctx || !wrapped || !session_key) return WBC_ERR_ARG;
    try {
        CtrSessionKey(ctx->prog, wrapped, wrapped + WBC_BLOCK_BYTES, session_key);
        return WBC_OK;
    } catch (...) {
        return WBC_ERR_NOMEM;
    }
}

/* ---- Bulk data helpers ---------------------------------------------------
 *
 * These are conventional XChaCha20-Poly1305, NOT white-box protected. They are
 * the data mover of the key-wrapping pattern above: the white-box wraps a
 * session key, these move the payload. See the contract and the memory-exposure
 * caveat in wbcrypto.h.
 */
wbc_status wbc_random(uint8_t* buf, size_t len) {
    if (!buf && len) return WBC_ERR_ARG;
    if (!EnsureSodium()) return WBC_ERR_NOMEM;
    if (len) randombytes_buf(buf, len);
    return WBC_OK;
}

void wbc_wipe(void* p, size_t len) {
    if (p && len) sodium_memzero(p, len);
}

wbc_status wbc_bulk_seal(const uint8_t key[WBC_SESSION_KEY_BYTES], const uint8_t* in,
                         size_t len, uint8_t* out, size_t* out_len) {
    if (!key || !out || !out_len || (!in && len)) return WBC_ERR_ARG;
    if (len > SIZE_MAX - WBC_BULK_OVERHEAD) return WBC_ERR_ARG;
    if (!EnsureSodium()) return WBC_ERR_NOMEM;

    /* Random nonce, prepended, so callers never have to manage one. At 24 bytes
     * random selection is safe for any realistic number of messages. */
    randombytes_buf(out, kNonce);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(out + kNonce, &ct_len, in, len,
                                                   nullptr, 0, nullptr, out,
                                                   key) != 0)
        return WBC_ERR_NOMEM;
    *out_len = kNonce + static_cast<size_t>(ct_len);
    return WBC_OK;
}

wbc_status wbc_bulk_open(const uint8_t key[WBC_SESSION_KEY_BYTES], const uint8_t* in,
                         size_t len, uint8_t* out, size_t* out_len) {
    if (!key || !in || !out_len) return WBC_ERR_ARG;
    if (len < WBC_BULK_OVERHEAD) return WBC_ERR_ARG;
    if (!out && len > WBC_BULK_OVERHEAD) return WBC_ERR_ARG;
    if (!EnsureSodium()) return WBC_ERR_NOMEM;

    unsigned long long pt_len = 0;
    /* Verifies the tag before releasing any plaintext, so a forgery writes
     * nothing to `out`. */
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &pt_len, nullptr,
                                                   in + kNonce, len - kNonce,
                                                   nullptr, 0, in, key) != 0)
        return WBC_ERR_AUTH;
    *out_len = static_cast<size_t>(pt_len);
    return WBC_OK;
}

void wbc_close(wbc_ctx* ctx) { delete ctx; }

void wbc_free(void* p) { std::free(p); }

}  // extern "C"
