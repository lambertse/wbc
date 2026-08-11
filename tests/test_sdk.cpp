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

        // There is no bulk round-trip to test: the SDK ships no bulk cipher, the
        // caller moves the payload with its own. What used to be tested here was
        // libsodium's AEAD, not ours.

        // wbc_wipe actually clears.
        wbc_wipe(sk, sizeof sk);
        bool all_zero = true;
        for (unsigned char c : sk) all_zero = all_zero && (c == 0);
        CHECK(all_zero);

        CHECK(wbc_random(nullptr, 4) == WBC_ERR_ARG);
    }

    // ---- every byte of a wrapped key is load-bearing ------------------------
    // wbc_wrap_key is deliberately NOT separately authenticated, so the header
    // owes the caller a precise promise: unwrapping a corrupted `wrapped` still
    // returns WBC_OK, but yields a DIFFERENT session key, which the caller's own
    // cipher is then responsible for noticing.
    //
    // This used to be tested by handing the wrong key to wbc_bulk_open and
    // watching the AEAD reject it — which really tested libsodium. Testing OUR
    // code means asserting the promise directly, and over the WHOLE buffer: flip
    // one bit in each of the 48 byte positions in turn and every one must change
    // the recovered key. That covers the IV half and the ciphertext half, and it
    // is what fails if the CTR keystream is ever truncated or an IV byte stops
    // reaching the counter block — bugs a single spot-check at index 0 and index
    // 16 would both walk straight past.
    {
        uint8_t sk[WBC_SESSION_KEY_BYTES], wrapped[WBC_WRAPPED_KEY_BYTES];
        CHECK(wbc_random(sk, sizeof sk) == WBC_OK);
        CHECK(wbc_wrap_key(ctx, sk, wrapped) == WBC_OK);

        // Sanity: the pristine wrap round-trips, so a failure below is the
        // corruption talking and not a broken wrap.
        uint8_t good_sk[WBC_SESSION_KEY_BYTES];
        CHECK(wbc_unwrap_key(ctx, wrapped, good_sk) == WBC_OK);
        CHECK(std::memcmp(sk, good_sk, sizeof sk) == 0);

        for (size_t i = 0; i < WBC_WRAPPED_KEY_BYTES; ++i) {
            wrapped[i] ^= 0x01;
            uint8_t bad_sk[WBC_SESSION_KEY_BYTES];
            // Unwrap cannot tell -- CTR has nothing to check.
            CHECK(wbc_unwrap_key(ctx, wrapped, bad_sk) == WBC_OK);
            // But the key it hands back is not the one that was wrapped.
            CHECK(std::memcmp(sk, bad_sk, sizeof sk) != 0);
            wrapped[i] ^= 0x01;
        }
        // ...and the buffer is back to pristine, so the flips really were undone.
        CHECK(wbc_unwrap_key(ctx, wrapped, good_sk) == WBC_OK);
        CHECK(std::memcmp(sk, good_sk, sizeof sk) == 0);
        std::printf("  [wrap] all %d bytes of a wrapped key affect the unwrapped key\n",
                    WBC_WRAPPED_KEY_BYTES);
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
