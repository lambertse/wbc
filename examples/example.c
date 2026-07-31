/* example.c — how a native project integrates the White-box Crypto VM SDK.
 *
 * This demo shows the FULL lifecycle (seal a key + run), so it links the
 * host-only PROVISIONING library (libwbprovision), which contains wbc_seal_key.
 *
 * A real FIELD app does NOT seal on-device: it links only the runtime library
 *   cc app.c -I../include -L../build -lwbcrypto -o app
 * and calls only wbc_open / wbc_encrypt_* on a blob produced offline by the
 * provisioning tool (wb_keygen). The runtime libwbcrypto.so deliberately does
 * not export wbc_seal_key or the reference AES / white-box generator. See
 * docs/SDK.md and docs/BUILD.md.
 */
#include <stdio.h>
#include <string.h>

#include "wbcrypto.h"

static void print_hex(const char* label, const uint8_t* p, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    printf("wbcrypto version %s\n", wbc_version());

    /* FIPS-197 key + plaintext. */
    const uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                             0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const uint8_t pt[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const char* pass = "integration-demo";

    /* 1. Seal the key into a blob (would normally be done once, offline). */
    uint8_t* blob = NULL;
    size_t blob_len = 0;
    wbc_status s = wbc_seal_key(key, pass, /*seed=*/42, /*hardened=*/1,
                                &blob, &blob_len);
    if (s != WBC_OK) { fprintf(stderr, "seal: %s\n", wbc_strerror(s)); return 1; }
    printf("sealed blob: %zu bytes\n", blob_len);

    /* 2. Open the blob at runtime. */
    wbc_ctx* ctx = NULL;
    s = wbc_open(blob, blob_len, pass, &ctx);
    if (s != WBC_OK) { fprintf(stderr, "open: %s\n", wbc_strerror(s)); return 1; }

    /* 3. ECB single block — matches standard AES-128 (69c4e0d8...). */
    uint8_t ct[16];
    wbc_encrypt_block(ctx, pt, ct);
    print_hex("ECB block:   ", ct, 16);

    /* 4. CTR mode encrypts AND decrypts arbitrary-length data. */
    const char* msg = "white-box AES inside a virtual machine!";
    size_t mlen = strlen(msg);
    uint8_t iv[16] = {0};
    uint8_t enc[64], dec[64];
    wbc_crypt_ctr(ctx, iv, (const uint8_t*)msg, enc, mlen);
    print_hex("CTR cipher:  ", enc, mlen);
    wbc_crypt_ctr(ctx, iv, enc, dec, mlen);   /* same call decrypts */
    dec[mlen] = '\0';
    printf("CTR decrypt: %s\n", dec);
    printf("round-trip:  %s\n", memcmp(msg, dec, mlen) == 0 ? "OK" : "FAIL");

    wbc_close(ctx);
    wbc_free(blob);
    return 0;
}
