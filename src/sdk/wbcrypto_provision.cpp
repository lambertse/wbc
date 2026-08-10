// wbcrypto_provision.cpp — C ABI PROVISIONING implementation.
//
// This translation unit contains the key-generation surface of the SDK:
// wbc_seal_key. It consumes a cleartext AES key and pulls in the reference AES,
// the white-box generator, and the bytecode assembler.
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
#include "wbaes/wb_generator.h"

extern "C" {

wbc_status wbc_seal_key(const uint8_t key[WBC_KEY_BYTES], const char* passphrase,
                        uint64_t seed, int hardened, wbc_kdf_tier tier,
                        uint8_t** out_blob, size_t* out_len) {
    if (!key || !out_blob || !out_len) return WBC_ERR_ARG;
    /* Reject an unknown tier here rather than letting it reach Seal: a blob is
     * sealed once and opened forever, so a bogus tier must not be persistable. */
    if (!storage::IsValidTier(static_cast<uint32_t>(tier))) return WBC_ERR_ARG;
    try {
        wbaes::Key128 k{};
        std::memcpy(k.data(), key, WBC_KEY_BYTES);
        auto wb = wbaes::GenerateWhiteBox(k, seed, wbaes::WBLevel::Internal);
        vm::ObfOptions obf = hardened ? vm::ObfOptions::All() : vm::ObfOptions::None();
        vm::Program prog = vm::AssembleWhiteBox(*wb, seed ^ 0x9999u, obf);
        std::string pass = passphrase ? passphrase : "";
        std::vector<uint8_t> blob =
            storage::Seal(prog, pass, static_cast<storage::KdfTier>(tier));

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

}  // extern "C"
