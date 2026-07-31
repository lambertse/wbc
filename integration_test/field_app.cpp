// field_app.cpp — a *third-party integration* of the White-box Crypto VM SDK.
//
// This is the artifact that the static-analysis assessment (docs/WBC_static_assessment.md)
// was MISSING. That review had only { libwbcrypto.so, sealed.blob, wbcrypto.h } and so
// could not see where the opening passphrase comes from — it had to assume the blob might
// be gated by a strong external secret ("Case B", not recoverable).
//
// A real field app links ONLY the runtime library and calls wbc_open / wbc_encrypt_*.
// It must supply the passphrase that seals the blob at rest. Here that passphrase is
// compiled into the binary (the common "auto-opening sealed storage" pattern) — which is
// exactly what puts the deployment in the assessment's "Case A": once you own this app,
// you own the passphrase, Layer 1 (the AEAD envelope) falls, and the white-box tables are
// exposed for cryptanalysis.
//
// The blob shipped here was produced by scripts/gen_blob.sh with its defaults:
//     key  = 000102030405060708090a0b0c0d0e0f   (FIPS-197 test key)
//     pass = "demo"
//     seed = 42
// Because the sealed key is the FIPS-197 vector, we can *confirm* the recovered key with a
// known-answer test: the white-box, once opened, must behave as standard AES-128-ECB.
//
// Build: see CMakeLists.txt in this directory.
// Run:   ./field_app [path/to/sealed.blob] [passphrase]

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "wbcrypto.h"

// Passphrase baked into the field binary. Override at build time with
//   -DWBC_APP_PASSPHRASE=\"...\"  or at runtime via argv[2].
#ifndef WBC_APP_PASSPHRASE
#define WBC_APP_PASSPHRASE "demo"
#endif

static void print_hex(const char* label, const uint8_t* p, size_t n) {
    std::printf("%s", label);
    for (size_t i = 0; i < n; ++i) std::printf("%02x", p[i]);
    std::printf("\n");
}

static bool read_file(const char* path, std::vector<uint8_t>& out) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 0) { std::fclose(f); return false; }
    out.resize(static_cast<size_t>(sz));
    size_t got = std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

int main(int argc, char** argv) {
    const char* blob_path = (argc > 1) ? argv[1] : "sealed.blob";
    const char* pass      = (argc > 2) ? argv[2] : WBC_APP_PASSPHRASE;

    std::printf("wbcrypto version %s\n", wbc_version());
    std::printf("opening blob:   %s\n", blob_path);
    std::printf("passphrase:     \"%s\"  (compiled into this field binary)\n", pass);

    // 1. Load the sealed blob shipped with the app.
    std::vector<uint8_t> blob;
    if (!read_file(blob_path, blob)) {
        std::fprintf(stderr, "ERROR: cannot read blob file '%s'\n", blob_path);
        return 2;
    }
    std::printf("blob size:      %zu bytes\n", blob.size());

    // 2. Open it. This is Layer 1: Argon2id(passphrase, salt) -> ChaCha20-Poly1305
    //    decrypt of the table bank. A wrong passphrase fails AEAD authentication.
    wbc_ctx* ctx = nullptr;
    wbc_status s = wbc_open(blob.data(), blob.size(), pass, &ctx);
    if (s != WBC_OK) {
        std::fprintf(stderr, "wbc_open failed: %s\n", wbc_strerror(s));
        std::fprintf(stderr, "(wrong passphrase or tampered blob -> AEAD auth failure)\n");
        return 3;
    }
    std::printf("wbc_open:       OK  (Layer 1 cleared — table bank decrypted in memory)\n\n");

    // 3. Use the sealed key. The runtime API exposes the key only as an ENCRYPTION
    //    ORACLE (it never hands back the 16 raw bytes). We drive that oracle with the
    //    FIPS-197 known-answer vector to CONFIRM which key is sealed inside.
    const uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                             0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t expect_ct[16] = {  // AES-128(000102..0f, 00112233..ff)  (FIPS-197 C.1)
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    const uint8_t sealed_key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    uint8_t ct[16];
    s = wbc_encrypt_block(ctx, pt, ct);
    if (s != WBC_OK) {
        std::fprintf(stderr, "wbc_encrypt_block failed: %s\n", wbc_strerror(s));
        wbc_close(ctx);
        return 4;
    }
    print_hex("plaintext:      ", pt, 16);
    print_hex("white-box ct:   ", ct, 16);
    print_hex("AES-128 ref ct: ", expect_ct, 16);

    bool kat_ok = std::memcmp(ct, expect_ct, 16) == 0;
    std::printf("KAT:            %s\n\n", kat_ok ? "MATCH — behaves as standard AES-128"
                                                 : "MISMATCH");

    if (kat_ok) {
        // The oracle reproduced the FIPS-197 vector, so the key diffused into the
        // (now-decrypted) white-box tables is exactly this one.
        print_hex(">> Sealed AES-128 key confirmed: ", sealed_key, 16);
        std::printf("   (Known-answer confirmation. Recovering the 16 bytes from an\n"
                    "    UNKNOWN key would require white-box cryptanalysis — BGE-family\n"
                    "    attack on these decrypted tables, ~2^22..2^32 — which this\n"
                    "    integration has now made possible by clearing Layer 1.)\n\n");
    }

    // 4. Realistic usage: CTR mode encrypts and decrypts arbitrary-length data.
    const char* msg = "white-box AES inside a virtual machine!";
    size_t mlen = std::strlen(msg);
    uint8_t iv[16] = {0};
    std::vector<uint8_t> enc(mlen), dec(mlen + 1);
    wbc_crypt_ctr(ctx, iv, reinterpret_cast<const uint8_t*>(msg), enc.data(), mlen);
    print_hex("CTR cipher:     ", enc.data(), mlen);
    wbc_crypt_ctr(ctx, iv, enc.data(), dec.data(), mlen);  // same call decrypts
    dec[mlen] = '\0';
    std::printf("CTR decrypt:    %s\n", reinterpret_cast<char*>(dec.data()));
    std::printf("round-trip:     %s\n",
                std::memcmp(msg, dec.data(), mlen) == 0 ? "OK" : "FAIL");

    wbc_close(ctx);
    return kat_ok ? 0 : 5;
}
