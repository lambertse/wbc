// wbcrypto_provision.cpp — C ABI PROVISIONING implementation.
//
// This translation unit contains the key-generation surface of the SDK:
// wbc_seal_key and wbc_export_tables. Both consume a cleartext AES key and pull
// in the reference AES, the white-box generator, and the bytecode assembler.
//
// It MUST NOT ship in the field runtime library (libwbcrypto.{a,so}); it is
// linked only into the provisioning tools (wb_keygen) and libwbprovision.a,
// which stay on the build/provisioning host. Shipping GenerateWhiteBox next to
// the runtime would put the reference cipher and the table generator on the
// attacker's device. See docs/BUILD.md.
#define WBC_BUILD
#include "wbcrypto.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#include "storage/trusted_storage.h"
#include "vm/assembler.h"
#include "wbaes/wb_export.h"
#include "wbaes/wb_generator.h"

extern "C" {

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

}  // extern "C"
