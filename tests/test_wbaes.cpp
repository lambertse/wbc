// Milestone B: the Chow white-box must compute plain AES at every stratum.
// Testing after each encoding layer localises any "encodings don't cancel" bug.
#include "test_util.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"
#include "wbaes/wb_interp.h"

using namespace wbaes;

static Key128 RandomKey(uint32_t& st) {
    Key128 k{};
    for (auto& b : k) { st = st * 1664525u + 1013904223u; b = static_cast<uint8_t>(st >> 24); }
    return k;
}

static void CheckMatchesAes(WBLevel level, const char* name, uint64_t seed,
                            const Key128& key, bool check_fips) {
    auto wb = GenerateWhiteBox(key, seed, level);

    if (check_fips) {
        // FIPS-197 known-answer vector (only meaningful for the FIPS key).
        Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
        Block wb_ct = WhiteBoxEncrypt(*wb, pt);
        Block ref_ct = AesEncryptBlock(pt, key);
        if (wb_ct != ref_ct) {
            std::printf("  FAIL [%s] FIPS vector: got %s want %s\n", name,
                        test::ToHex(wb_ct.data(), 16).c_str(),
                        test::ToHex(ref_ct.data(), 16).c_str());
            ++test::failures();
        }
    }

    // Randomised differential test against the reference oracle.
    uint32_t st = 0x1234567u ^ static_cast<uint32_t>(seed);
    for (int trial = 0; trial < 256; ++trial) {
        Block p{};
        for (auto& b : p) {
            st = st * 1664525u + 1013904223u;
            b = static_cast<uint8_t>(st >> 24);
        }
        if (WhiteBoxEncrypt(*wb, p) != AesEncryptBlock(p, key)) {
            std::printf("  FAIL [%s] random block trial %d\n", name, trial);
            ++test::failures();
            break;
        }
    }
    std::printf("  [%s] checked (seed=%llu)\n", name,
                static_cast<unsigned long long>(seed));
}

int main() {
    Key128 fips = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    // Stratum 1: naked network, no encodings.
    CheckMatchesAes(WBLevel::Naked, "naked", 1, fips, /*check_fips=*/true);
    // Stratum 2: random internal nibble encodings + type-IV XOR (must cancel).
    for (uint64_t seed : {1ull, 2ull, 42ull, 0xDEADBEEFull})
        CheckMatchesAes(WBLevel::Internal, "internal", seed, fips, true);

    // Random-key dimension: exercises key expansion + k10 dst-folding for keys
    // other than the FIPS vector (the one class of key-handling bug the fixed
    // vector cannot see).
    uint32_t kst = 0x51ED776Fu;
    for (int t = 0; t < 8; ++t) {
        Key128 rk = RandomKey(kst);
        CheckMatchesAes(WBLevel::Naked, "naked-randkey", 100 + t, rk, false);
        CheckMatchesAes(WBLevel::Internal, "internal-randkey", 200 + t, rk, false);
    }

    return test::Report("test_wbaes");
}
