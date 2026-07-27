// Milestone A: verify the reference AES-128 oracle against the FIPS-197 vector.
// Until this passes, nothing downstream can be trusted.
#include "test_util.h"
#include "wbaes/aes_ref.h"
#include "wbaes/gf256.h"

using namespace wbaes;

int main() {
    // GF(2^8) sanity.
    CHECK(gf::mul(0x57, 0x83) == 0xc1);   // classic FIPS example
    CHECK(gf::mul(0x02, 0x02) == 0x04);
    CHECK(gf::mul(gf::inv(0x53), 0x53) == 0x01);
    CHECK(kSBox[0x00] == 0x63);
    CHECK(kSBox[0x53] == 0xed);

    // FIPS-197 Appendix B / C.1 known-answer test.
    Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    Block ct = AesEncryptBlock(pt, key);
    CHECK_EQ_HEX(ct.data(), 16, "69c4e0d86a7b0430d8cdb78070b4c55a");

    // FIPS-197 Appendix A key-expansion spot check: last round key word.
    auto rk = KeyExpansion(key);
    CHECK_EQ_HEX(&rk[160], 16, "13111d7fe3944a17f307a78b4d2b30c5");

    return test::Report("test_aes_ref");
}
