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

extern "C" {

const char* wbc_version(void) { return "1.0.0"; }

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
        std::vector<uint8_t> b(blob, blob + blob_len);
        std::string pass = passphrase ? passphrase : "";
        if (!storage::Unseal(b, pass, ctx->prog)) {
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

wbc_status wbc_encrypt_ecb(wbc_ctx* ctx, const uint8_t* in, uint8_t* out,
                           size_t len) {
    if (!ctx || !in || !out) return WBC_ERR_ARG;
    if (len % 16 != 0) return WBC_ERR_ARG;
    for (size_t off = 0; off < len; off += 16) {
        wbc_status s = wbc_encrypt_block(ctx, in + off, out + off);
        if (s != WBC_OK) return s;
    }
    return WBC_OK;
}

wbc_status wbc_crypt_ctr(wbc_ctx* ctx, const uint8_t iv[WBC_BLOCK_BYTES],
                         const uint8_t* in, uint8_t* out, size_t len) {
    if (!ctx || !iv || (!in && len) || (!out && len)) return WBC_ERR_ARG;
    try {
        std::array<uint8_t, 16> counter{};
        std::memcpy(counter.data(), iv, 16);
        size_t off = 0;
        while (off < len) {
            auto ks = vm::Run(ctx->prog, counter);  // keystream block = E(counter)
            size_t n = (len - off < 16) ? (len - off) : 16;
            for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ ks[i];
            off += n;
            // big-endian 128-bit counter increment
            for (int i = 15; i >= 0; --i) {
                if (++counter[i] != 0) break;
            }
        }
        return WBC_OK;
    } catch (...) {
        return WBC_ERR_NOMEM;
    }
}

/* ---- Bulk data helpers ---------------------------------------------------
 *
 * These are conventional XChaCha20-Poly1305, NOT white-box protected. They
 * exist so callers stop pushing megabytes through the VM at 0.045 MB/s: the
 * white-box wraps a session key, these move the payload. See the contract and
 * the memory-exposure caveat in wbcrypto.h.
 *
 * Sizes are checked against the libsodium constants with static_assert rather
 * than assumed, so a libsodium upgrade that changed them is a build error
 * instead of a buffer overflow.
 */
static_assert(WBC_SESSION_KEY_BYTES == crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
              "WBC_SESSION_KEY_BYTES must track libsodium's KEYBYTES");
static_assert(WBC_BULK_OVERHEAD == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                       crypto_aead_xchacha20poly1305_ietf_ABYTES,
              "WBC_BULK_OVERHEAD must track libsodium's NPUBBYTES + ABYTES");

namespace {
constexpr size_t kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24

/* sodium_init() is idempotent; <0 means the RNG is unusable. */
bool EnsureSodium() { return sodium_init() >= 0; }
}  // namespace

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
