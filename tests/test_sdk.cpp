// SDK C-ABI test: exercises wbcrypto.h end to end (seal -> open -> encrypt),
// CTR round-trip, aliasing, and error paths. Included from C++ but uses only
// the extern "C" surface a native integrator would see.
#include <cstring>
#include <vector>

#include "test_util.h"
#include "wbaes/aes_ref.h"   // oracle for cross-check
#include "wbcrypto.h"

using wbaes::AesEncryptBlock;

int main() {
    wbaes::Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    wbaes::Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");

    // seal + open
    uint8_t* blob = nullptr; size_t blen = 0;
    // Most of this file exercises the C ABI, not the KDF, so it seals at
    // WBC_KDF_NONE to keep the suite fast. The tier itself is covered
    // explicitly (all three, plus rejection of an invalid one) further down.
    CHECK(wbc_seal_key(key.data(), "pw", 42, /*hardened=*/1, WBC_KDF_NONE, &blob,
                       &blen) == WBC_OK);
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
        CHECK(wbc_seal_key(key.data(), "pw", 42, 1, WBC_KDF_NONE, &blob2, &blen2) == WBC_OK);
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
    // the KDF and unseals to the correct FIPS vector.
    {
        uint8_t* nblob = nullptr; size_t nlen = 0;
        CHECK(wbc_seal_key(key.data(), nullptr, 7, 1, WBC_KDF_NONE, &nblob, &nlen) == WBC_OK);
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

    // ---- key wrapping: the SDK's only data-bearing pattern ------------------
    // The white-box wraps a session key; a conventional AEAD moves the data.
    {
        uint8_t sk[WBC_SESSION_KEY_BYTES], sk_unwrapped[WBC_SESSION_KEY_BYTES];
        uint8_t wrapped[WBC_WRAPPED_KEY_BYTES];
        CHECK(wbc_random(sk, sizeof sk) == WBC_OK);

        CHECK(wbc_wrap_key(ctx, sk, wrapped) == WBC_OK);
        // The wrapped key must not contain the plaintext key anywhere in it.
        CHECK(std::memcmp(sk, wrapped + WBC_BLOCK_BYTES, sizeof sk) != 0);
        CHECK(wbc_unwrap_key(ctx, wrapped, sk_unwrapped) == WBC_OK);
        CHECK(std::memcmp(sk, sk_unwrapped, sizeof sk) == 0);

        // The IV is generated INSIDE wbc_wrap_key so it cannot be reused: CTR
        // with a repeated IV under the same long-term key leaks the XOR of two
        // session keys. Wrapping the SAME key twice must therefore produce
        // different bytes. This is the test that keeps that guarantee honest --
        // pin the IV to a constant and it fails.
        uint8_t wrapped2[WBC_WRAPPED_KEY_BYTES];
        CHECK(wbc_wrap_key(ctx, sk, wrapped2) == WBC_OK);
        CHECK(std::memcmp(wrapped, wrapped2, WBC_WRAPPED_KEY_BYTES) != 0);
        // ...and both still unwrap to the same key.
        uint8_t sk3[WBC_SESSION_KEY_BYTES];
        CHECK(wbc_unwrap_key(ctx, wrapped2, sk3) == WBC_OK);
        CHECK(std::memcmp(sk, sk3, sizeof sk) == 0);

        // Argument checks on the new pair.
        CHECK(wbc_wrap_key(nullptr, sk, wrapped) == WBC_ERR_ARG);
        CHECK(wbc_wrap_key(ctx, nullptr, wrapped) == WBC_ERR_ARG);
        CHECK(wbc_unwrap_key(ctx, wrapped, nullptr) == WBC_ERR_ARG);

        // Bulk round-trip, including a 0-length payload and an odd length.
        for (size_t n : {size_t{0}, size_t{1}, size_t{4095}}) {
            std::vector<uint8_t> in(n), sealed(n + WBC_BULK_OVERHEAD), opened(n ? n : 1);
            for (size_t i = 0; i < n; ++i) in[i] = static_cast<uint8_t>(i * 7 + 3);
            size_t sealed_len = 0, opened_len = 0;
            CHECK(wbc_bulk_seal(sk, in.data(), n, sealed.data(), &sealed_len) == WBC_OK);
            CHECK(sealed_len == n + WBC_BULK_OVERHEAD);
            CHECK(wbc_bulk_open(sk, sealed.data(), sealed_len, opened.data(),
                                &opened_len) == WBC_OK);
            CHECK(opened_len == n);
            CHECK(n == 0 || std::memcmp(in.data(), opened.data(), n) == 0);

            // Any single-bit change anywhere must fail authentication, and a
            // wrong key must not decrypt.
            sealed[sealed_len / 2] ^= 0x01;
            CHECK(wbc_bulk_open(sk, sealed.data(), sealed_len, opened.data(),
                                &opened_len) == WBC_ERR_AUTH);
            sealed[sealed_len / 2] ^= 0x01;
            uint8_t wrong[WBC_SESSION_KEY_BYTES];
            std::memcpy(wrong, sk, sizeof wrong);
            wrong[0] ^= 0x80;
            CHECK(wbc_bulk_open(wrong, sealed.data(), sealed_len, opened.data(),
                                &opened_len) == WBC_ERR_AUTH);
        }

        // Two seals of the same plaintext must differ (fresh random nonce).
        uint8_t a[WBC_BULK_OVERHEAD + 8], b[WBC_BULK_OVERHEAD + 8];
        const uint8_t msg[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        size_t alen = 0, blen2 = 0;
        CHECK(wbc_bulk_seal(sk, msg, sizeof msg, a, &alen) == WBC_OK);
        CHECK(wbc_bulk_seal(sk, msg, sizeof msg, b, &blen2) == WBC_OK);
        CHECK(alen == blen2 && std::memcmp(a, b, alen) != 0);

        // wbc_wipe actually clears.
        wbc_wipe(sk, sizeof sk);
        bool all_zero = true;
        for (unsigned char c : sk) all_zero = all_zero && (c == 0);
        CHECK(all_zero);

        // error paths on the bulk surface.
        size_t dummy = 0;
        CHECK(wbc_bulk_open(sk, a, WBC_BULK_OVERHEAD - 1, b, &dummy) == WBC_ERR_ARG);
        CHECK(wbc_bulk_seal(nullptr, msg, sizeof msg, a, &dummy) == WBC_ERR_ARG);
        CHECK(wbc_random(nullptr, 4) == WBC_ERR_ARG);
    }

    // ---- corrupting a wrapped key is detected downstream --------------------
    // wbc_wrap_key is deliberately NOT separately authenticated: a corrupted
    // wrapped key unwraps to a WRONG session key, and the AEAD then rejects the
    // payload. That is the argument for not adding a second MAC, so it needs to
    // be a test rather than a claim in a comment.
    {
        uint8_t sk[WBC_SESSION_KEY_BYTES], wrapped[WBC_WRAPPED_KEY_BYTES];
        CHECK(wbc_random(sk, sizeof sk) == WBC_OK);
        CHECK(wbc_wrap_key(ctx, sk, wrapped) == WBC_OK);

        const uint8_t payload[64] = {0};
        uint8_t sealed[64 + WBC_BULK_OVERHEAD], opened[64];
        size_t sealed_len = 0, opened_len = 0;
        CHECK(wbc_bulk_seal(sk, payload, sizeof payload, sealed, &sealed_len) == WBC_OK);

        // Flip a bit in the wrapped key's ciphertext half...
        wrapped[WBC_BLOCK_BYTES] ^= 0x01;
        uint8_t bad_sk[WBC_SESSION_KEY_BYTES];
        CHECK(wbc_unwrap_key(ctx, wrapped, bad_sk) == WBC_OK);   // unwrap cannot tell
        CHECK(std::memcmp(sk, bad_sk, sizeof sk) != 0);          // but the key is wrong
        CHECK(wbc_bulk_open(bad_sk, sealed, sealed_len, opened,
                            &opened_len) == WBC_ERR_AUTH);       // and the AEAD catches it
        wrapped[WBC_BLOCK_BYTES] ^= 0x01;

        // ...and flipping the IV half is caught the same way.
        wrapped[0] ^= 0x80;
        CHECK(wbc_unwrap_key(ctx, wrapped, bad_sk) == WBC_OK);
        CHECK(std::memcmp(sk, bad_sk, sizeof sk) != 0);
        CHECK(wbc_bulk_open(bad_sk, sealed, sealed_len, opened,
                            &opened_len) == WBC_ERR_AUTH);
        std::printf("  [wrap] corrupted wrapped key -> WBC_ERR_AUTH from the AEAD\n");
    }

    // ---- KDF tiers ---------------------------------------------------------
    // Every tier must seal, report itself, and open to the same ciphertext: the
    // tier changes ONLY the cost of deriving the seal key, never the white-box.
    // (WBC_KDF_HIGH here is the slow one — one Argon2id seal plus one open.)
    {
        const wbc_kdf_tier tiers[] = {WBC_KDF_NONE, WBC_KDF_LOW, WBC_KDF_HIGH};
        for (wbc_kdf_tier t : tiers) {
            uint8_t* tb = nullptr; size_t tl = 0;
            CHECK(wbc_seal_key(key.data(), "pw", 42, 1, t, &tb, &tl) == WBC_OK);

            // The tier is readable from the header without a passphrase and
            // without paying the KDF.
            wbc_kdf_tier got = WBC_KDF_HIGH;
            CHECK(wbc_blob_kdf_tier(tb, tl, &got) == WBC_OK);
            CHECK(got == t);

            wbc_ctx* tc = nullptr;
            CHECK(wbc_open(tb, tl, "pw", &tc) == WBC_OK);
            uint8_t tct[16];
            CHECK(wbc_encrypt_block(tc, pt.data(), tct) == WBC_OK);
            CHECK(std::memcmp(tct, ref.data(), 16) == 0);

            // A downgrade is not an oracle: the tier lives in the AEAD's
            // associated data, so rewriting it changes both the derived key and
            // the authenticated data and the tag fails. Stamp a *valid* other
            // tier so this tests the AD binding, not the range check.
            {
                std::vector<uint8_t> d(tb, tb + tl);
                d[8] = static_cast<uint8_t>(t == WBC_KDF_NONE ? WBC_KDF_LOW : WBC_KDF_NONE);
                wbc_ctx* dc = nullptr;
                CHECK(wbc_open(d.data(), d.size(), "pw", &dc) == WBC_ERR_FORMAT);
                CHECK(dc == nullptr);
            }

            // An out-of-range tier is refused outright, before any derivation.
            {
                std::vector<uint8_t> bad(tb, tb + tl);
                bad[8] = 0x7F;
                wbc_ctx* bc = nullptr;
                CHECK(wbc_open(bad.data(), bad.size(), "pw", &bc) == WBC_ERR_FORMAT);
                wbc_kdf_tier ignored;
                CHECK(wbc_blob_kdf_tier(bad.data(), bad.size(), &ignored) == WBC_ERR_FORMAT);
            }

            wbc_close(tc); wbc_free(tb);
        }
        std::printf("  [kdf] all 3 tiers seal/report/open; downgrade and bad tier refused\n");
    }

    // error paths.
    CHECK(wbc_open(blob, 3, "pw", &ctx) == WBC_ERR_FORMAT);
    CHECK(wbc_seal_key(nullptr, "pw", 0, 1, WBC_KDF_NONE, &blob, &blen) == WBC_ERR_ARG);
    // An unknown tier must not be sealable in the first place.
    {
        uint8_t* xb = nullptr; size_t xl = 0;
        CHECK(wbc_seal_key(key.data(), "pw", 0, 1, static_cast<wbc_kdf_tier>(99), &xb,
                           &xl) == WBC_ERR_ARG);
        CHECK(xb == nullptr);
    }
    CHECK(wbc_blob_kdf_tier(blob, 3, nullptr) == WBC_ERR_ARG);

    wbc_close(ctx); wbc_free(blob);
    return test::Report("test_sdk");
}
