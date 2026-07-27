// wbcrypto.cpp — C ABI implementation over the C++ white-box VM core.
//
// All entry points are noexcept boundaries: C++ exceptions (e.g. bad_alloc) are
// caught and translated to wbc_status codes so they never cross into C callers.
#define WBC_BUILD
#include "wbcrypto.h"

#include <cstdlib>
#include <cstring>
#include <new>

#include "storage/trusted_storage.h"
#include "vm/assembler.h"
#include "vm/vm.h"
#include "wbaes/wb_export.h"
#include "wbaes/wb_generator.h"

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
    }
    return "unknown";
}

wbc_status wbc_seal_key(const uint8_t key[WBC_KEY_BYTES], const char* passphrase,
                        uint64_t seed, int hardened, uint8_t** out_blob,
                        size_t* out_len) {
    if (!key || !out_blob || !out_len) return WBC_ERR_ARG;
    try {
        wbaes::Key128 k{};
        std::memcpy(k.data(), key, WBC_KEY_BYTES);
        auto wb = wbaes::GenerateWhiteBox(k, seed, wbaes::WBLevel::Internal);
        vm::ObfOptions obf = hardened ? vm::ObfOptions::All() : vm::ObfOptions::None();
        vm::Program prog = vm::AssembleWhiteBox(*wb, seed ^ 0x9999u, obf);
        std::string pass = passphrase ? passphrase : "";
        std::vector<uint8_t> blob = storage::Seal(prog, pass);

        uint8_t* buf = static_cast<uint8_t*>(std::malloc(blob.size()));
        if (!buf) return WBC_ERR_NOMEM;
        std::memcpy(buf, blob.data(), blob.size());
        *out_blob = buf;
        *out_len = blob.size();
        return WBC_OK;
    } catch (const std::bad_alloc&) {
        return WBC_ERR_NOMEM;
    } catch (...) {
        return WBC_ERR_ARG;
    }
}

wbc_status wbc_export_tables(const uint8_t key[WBC_KEY_BYTES], uint64_t seed,
                             uint8_t** out_image, size_t* out_len) {
    if (!key || !out_image || !out_len) return WBC_ERR_ARG;
    try {
        wbaes::Key128 k{};
        std::memcpy(k.data(), key, WBC_KEY_BYTES);
        auto wb = wbaes::GenerateWhiteBox(k, seed, wbaes::WBLevel::Internal);
        std::vector<uint8_t> img = wbaes::ExportTableImage(*wb);
        uint8_t* buf = static_cast<uint8_t*>(std::malloc(img.size()));
        if (!buf) return WBC_ERR_NOMEM;
        std::memcpy(buf, img.data(), img.size());
        *out_image = buf;
        *out_len = img.size();
        return WBC_OK;
    } catch (const std::bad_alloc&) {
        return WBC_ERR_NOMEM;
    } catch (...) {
        return WBC_ERR_ARG;
    }
}

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

void wbc_close(wbc_ctx* ctx) { delete ctx; }

void wbc_free(void* p) { std::free(p); }

}  // extern "C"
