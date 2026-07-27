// Freestanding runtime test: the device-side wb_stub.h, fed an exported table
// image, must reproduce AES and match the C++ white-box interpreter. Included
// from C++ but wb_stub.h itself uses no libc (see the separate freestanding
// compile-check in build.sh).
#include "test_util.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_export.h"
#include "wbaes/wb_generator.h"
#include "wbaes/wb_interp.h"
#include "wb_stub.h"

using namespace wbaes;

static void Check(const Key128& key, uint64_t seed, const char* name, bool fips) {
    auto wb = GenerateWhiteBox(key, seed, WBLevel::Internal);
    std::vector<uint8_t> img = ExportTableImage(*wb);
    CHECK(img.size() == WBTB_IMAGE_SIZE);
    CHECK(img[0] == 'W' && img[1] == 'B' && img[2] == 'T' && img[3] == 'B');

    if (fips) {
        Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
        uint8_t out[16];
        wbstub_encrypt_block(img.data(), pt.data(), out);
        CHECK_EQ_HEX(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    // Differential vs interpreter + oracle over random blocks.
    uint32_t st = 0xBEEF ^ static_cast<uint32_t>(seed);
    for (int trial = 0; trial < 64; ++trial) {
        Block p{};
        for (auto& x : p) { st = st * 1664525u + 1013904223u; x = static_cast<uint8_t>(st >> 24); }
        uint8_t out[16];
        wbstub_encrypt_block(img.data(), p.data(), out);
        Block iblk = WhiteBoxEncrypt(*wb, p);
        Block ablk = AesEncryptBlock(p, key);
        if (std::memcmp(out, iblk.data(), 16) != 0 ||
            std::memcmp(out, ablk.data(), 16) != 0) {
            std::printf("  FAIL [%s] trial %d\n", name, trial);
            ++test::failures();
            return;
        }
    }

    // CTR round-trip (encrypt then decrypt with the same call).
    const char* msg = "freestanding white-box AES-CTR on device";
    uint32_t mlen = static_cast<uint32_t>(std::strlen(msg));
    uint8_t iv[16] = {0};
    std::vector<uint8_t> enc(mlen), dec(mlen);
    wbstub_ctr_xcrypt(img.data(), iv, reinterpret_cast<const uint8_t*>(msg), enc.data(), mlen);
    CHECK(std::memcmp(enc.data(), msg, mlen) != 0);
    wbstub_ctr_xcrypt(img.data(), iv, enc.data(), dec.data(), mlen);
    CHECK(std::memcmp(dec.data(), msg, mlen) == 0);
    std::printf("  [%s] freestanding runtime matches AES (seed=%llu)\n", name,
                static_cast<unsigned long long>(seed));
}

int main() {
    Key128 fips = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    Check(fips, 12345, "fips", true);
    uint32_t kst = 0xA11CE;
    for (int t = 0; t < 4; ++t) {
        Key128 rk{};
        for (auto& b : rk) { kst = kst * 1664525u + 1013904223u; b = static_cast<uint8_t>(kst >> 24); }
        Check(rk, 500 + t, "randkey", false);
    }
    return test::Report("test_stub");
}
