// SDK C-ABI test: exercises wbcrypto.h end to end (seal -> open -> encrypt),
// CTR round-trip, aliasing, and error paths. Included from C++ but uses only
// the extern "C" surface a native integrator would see.
#include <cstring>

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

    // wrong passphrase -> AEAD auth fails, blob does not open (v2 contract).
    wbc_ctx* wctx = nullptr;
    CHECK(wbc_open(blob, blen, "nope", &wctx) == WBC_ERR_FORMAT);
    CHECK(wctx == nullptr);

    // tamper: flip one byte anywhere -> auth fails, does not open.
    {
        std::vector<uint8_t> t(blob, blob + blen);
        t[blen / 2] ^= 0x01;
        wbc_ctx* tctx = nullptr;
        CHECK(wbc_open(t.data(), t.size(), "pw", &tctx) == WBC_ERR_FORMAT);
        CHECK(tctx == nullptr);
    }

    // salt/nonce are random per seal -> same key+pass => different blob bytes.
    {
        uint8_t* blob2 = nullptr; size_t blen2 = 0;
        CHECK(wbc_seal_key(key.data(), "pw", 42, 1, &blob2, &blen2) == WBC_OK);
        CHECK(blen2 == blen);
        CHECK(std::memcmp(blob, blob2, blen) != 0);
        // ...but it still opens and encrypts identically.
        wbc_ctx* c2 = nullptr;
        CHECK(wbc_open(blob2, blen2, "pw", &c2) == WBC_OK);
        uint8_t ct2[16];
        CHECK(wbc_encrypt_block(c2, pt.data(), ct2) == WBC_OK);
        CHECK(std::memcmp(ct2, ref.data(), 16) == 0);
        wbc_close(c2); wbc_free(blob2);
    }

    // NULL passphrase (documented as "treated as empty") round-trips through
    // the Argon2id KDF and unseals to the correct FIPS vector.
    {
        uint8_t* nblob = nullptr; size_t nlen = 0;
        CHECK(wbc_seal_key(key.data(), nullptr, 7, 1, &nblob, &nlen) == WBC_OK);
        wbc_ctx* nctx = nullptr;
        CHECK(wbc_open(nblob, nlen, nullptr, &nctx) == WBC_OK);
        uint8_t nct[16];
        CHECK(wbc_encrypt_block(nctx, pt.data(), nct) == WBC_OK);
        CHECK(std::memcmp(nct, ref.data(), 16) == 0);
        // NULL == "" : a blob sealed with NULL opens with "" and vice versa.
        wbc_ctx* ectx = nullptr;
        CHECK(wbc_open(nblob, nlen, "", &ectx) == WBC_OK);
        wbc_close(nctx); wbc_close(ectx); wbc_free(nblob);
    }

    // error paths.
    CHECK(wbc_open(blob, 3, "pw", &ctx) == WBC_ERR_FORMAT);
    CHECK(wbc_seal_key(nullptr, "pw", 0, 1, &blob, &blen) == WBC_ERR_ARG);

    wbc_close(ctx); wbc_free(blob);
    return test::Report("test_sdk");
}
