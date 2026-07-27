// SDK C-ABI test: exercises wbcrypto.h end to end (seal -> open -> encrypt),
// CTR round-trip, aliasing, and error paths. Included from C++ but uses only
// the extern "C" surface a native integrator would see.
#include "test_util.h"
#include "wbaes/aes_ref.h"   // oracle for cross-check
#include "wbcrypto.h"

using wbaes::AesEncryptBlock;

int main() {
    wbaes::Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    wbaes::Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");

    // seal + open
    uint8_t* blob = nullptr; size_t blen = 0;
    CHECK(wbc_seal_key(key.data(), "pw", 42, /*hardened=*/1, &blob, &blen) == WBC_OK);
    CHECK(blob != nullptr && blen > 0);

    wbc_ctx* ctx = nullptr;
    CHECK(wbc_open(blob, blen, "pw", &ctx) == WBC_OK);

    // single block == standard AES.
    uint8_t ct[16];
    CHECK(wbc_encrypt_block(ctx, pt.data(), ct) == WBC_OK);
    CHECK_EQ_HEX(ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    wbaes::Block ref = AesEncryptBlock(pt, key);
    CHECK(std::memcmp(ct, ref.data(), 16) == 0);

    // in-place (aliasing) block encrypt.
    uint8_t buf[16]; std::memcpy(buf, pt.data(), 16);
    CHECK(wbc_encrypt_block(ctx, buf, buf) == WBC_OK);
    CHECK(std::memcmp(buf, ref.data(), 16) == 0);

    // ECB multi-block == per-block AES.
    uint8_t in3[48], out3[48];
    for (int i = 0; i < 48; ++i) in3[i] = static_cast<uint8_t>(i * 7 + 1);
    CHECK(wbc_encrypt_ecb(ctx, in3, out3, 48) == WBC_OK);
    for (int b = 0; b < 3; ++b) {
        wbaes::Block blk; std::memcpy(blk.data(), in3 + 16 * b, 16);
        wbaes::Block e = AesEncryptBlock(blk, key);
        CHECK(std::memcmp(out3 + 16 * b, e.data(), 16) == 0);
    }
    CHECK(wbc_encrypt_ecb(ctx, in3, out3, 47) == WBC_ERR_ARG);  // non-multiple

    // CTR encrypt then decrypt (same call) round-trips arbitrary length.
    const char* msg = "white-box AES in a VM, via the C SDK!";
    size_t mlen = std::strlen(msg);
    uint8_t iv[16] = {0};
    std::vector<uint8_t> enc(mlen), dec(mlen);
    CHECK(wbc_crypt_ctr(ctx, iv, reinterpret_cast<const uint8_t*>(msg), enc.data(), mlen) == WBC_OK);
    CHECK(std::memcmp(enc.data(), msg, mlen) != 0);  // actually transformed
    CHECK(wbc_crypt_ctr(ctx, iv, enc.data(), dec.data(), mlen) == WBC_OK);
    CHECK(std::memcmp(dec.data(), msg, mlen) == 0);

    // wrong passphrase -> opens but produces wrong output (no key leak).
    wbc_ctx* wctx = nullptr;
    CHECK(wbc_open(blob, blen, "nope", &wctx) == WBC_OK);
    uint8_t wct[16];
    CHECK(wbc_encrypt_block(wctx, pt.data(), wct) == WBC_OK);
    CHECK(std::memcmp(wct, ref.data(), 16) != 0);

    // error paths.
    CHECK(wbc_open(blob, 3, "pw", &ctx) == WBC_ERR_FORMAT);
    CHECK(wbc_seal_key(nullptr, "pw", 0, 1, &blob, &blen) == WBC_ERR_ARG);

    wbc_close(ctx); wbc_close(wctx); wbc_free(blob);
    return test::Report("test_sdk");
}
