/* keywrap.c — how to use this SDK. This is the only shape it offers.
 *
 * The white-box runs at well under 1 MB/s: every 16-byte block is thousands of
 * obfuscated VM instructions. That slowness IS the obfuscation — it cannot be
 * optimized away without deleting the protection. So the SDK deliberately has no
 * bulk entry point. You protect a KEY with the white-box and move the DATA
 * conventionally:
 *
 *     white-box   ──wraps──▶  32-byte session key   (2 blocks, ~0.5 ms, FIXED)
 *     session key ──seals──▶  the actual payload    (XChaCha20-Poly1305, GB/s)
 *
 * The white-box charge does not grow with the payload, so only the AEAD term
 * scales. A 5 MiB round trip is ~13 ms per leg.
 *
 * The long-term key is never reconstructed. What you give up is that the SESSION
 * key exists in plaintext memory between the unwrap and the wipe — see the
 * CAVEAT printed at the end, and include/wbcrypto.h.
 *
 * This demo seals its own blob for self-containment, so it links
 * libwbprovision. A field app links only libwbcrypto and calls wbc_open on a
 * blob produced offline by wb_keygen.
 *
 * Usage:  ./build/keywrap [payload-MiB]     (1..4096, default 1)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wbcrypto.h"

static size_t g_payload_bytes = 1u << 20; /* 1 MiB default */
#define PAYLOAD_BYTES g_payload_bytes

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void print_hex(const char* label, const uint8_t* p, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc > 1) {
        unsigned long mib = strtoul(argv[1], NULL, 10);
        if (mib == 0 || mib > 4096) {
            fprintf(stderr, "usage: %s [payload-MiB]   (1..4096, default 1)\n", argv[0]);
            return 2;
        }
        g_payload_bytes = (size_t)mib << 20;
    }

    const uint8_t long_term_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const char* pass = "keywrap-demo";
    wbc_status s;

    printf("wbcrypto version %s\n", wbc_version());

    uint8_t* blob = NULL;
    size_t blob_len = 0;
    s = wbc_seal_key(long_term_key, pass, 42, 1, &blob, &blob_len);
    if (s != WBC_OK) { fprintf(stderr, "seal: %s\n", wbc_strerror(s)); return 1; }

    wbc_ctx* ctx = NULL;
    s = wbc_open(blob, blob_len, pass, &ctx);
    if (s != WBC_OK) { fprintf(stderr, "open: %s\n", wbc_strerror(s)); return 1; }

    /* Casts are redundant in C, but kept so this file also compiles cleanly if
     * someone builds it as C++ (where void* does not convert implicitly). */
    uint8_t* payload = (uint8_t*)malloc(PAYLOAD_BYTES);
    uint8_t* sealed = (uint8_t*)malloc(PAYLOAD_BYTES + WBC_BULK_OVERHEAD);
    uint8_t* opened = (uint8_t*)malloc(PAYLOAD_BYTES);
    if (!payload || !sealed || !opened) { fprintf(stderr, "oom\n"); return 1; }
    for (size_t i = 0; i < PAYLOAD_BYTES; ++i) payload[i] = (uint8_t)(i * 31u + 7u);

    printf("payload: %zu bytes (%zu MiB)\n\n", PAYLOAD_BYTES, PAYLOAD_BYTES >> 20);

    /* ---- WRITE ---------------------------------------------------------- */
    double t0 = now_ms();

    uint8_t sk[WBC_SESSION_KEY_BYTES];
    s = wbc_random(sk, sizeof sk);
    if (s != WBC_OK) { fprintf(stderr, "random: %s\n", wbc_strerror(s)); return 1; }

    /* The white-box wraps the session key. No IV to manage: wbc_wrap_key
     * generates one internally and prepends it, so it cannot be reused. */
    uint8_t wrapped[WBC_WRAPPED_KEY_BYTES];
    double t_wrap0 = now_ms();
    s = wbc_wrap_key(ctx, sk, wrapped);
    double t_wrap = now_ms() - t_wrap0;
    if (s != WBC_OK) { fprintf(stderr, "wrap: %s\n", wbc_strerror(s)); return 1; }

    /* The session key seals the payload with a conventional AEAD. */
    size_t sealed_len = 0;
    double t_seal0 = now_ms();
    s = wbc_bulk_seal(sk, payload, PAYLOAD_BYTES, sealed, &sealed_len);
    double t_seal = now_ms() - t_seal0;
    if (s != WBC_OK) { fprintf(stderr, "bulk_seal: %s\n", wbc_strerror(s)); return 1; }

    /* Plaintext session key's job is done — drop it immediately. */
    wbc_wipe(sk, sizeof sk);
    double t_write = now_ms() - t0;

    printf("WRITE\n");
    printf("  wrap session key (white-box, 2 blocks) : %8.2f ms\n", t_wrap);
    printf("  seal payload     (conventional AEAD)   : %8.2f ms\n", t_seal);
    printf("  total                                  : %8.2f ms\n\n", t_write);

    /* ---- what you actually store or send -------------------------------- */
    /* Wire format: the 48-byte wrapped key, then the sealed payload. The wrapped
     * key already carries its own IV, and the sealed payload its own nonce, so
     * there is nothing else to keep track of. */
    size_t msg_len = WBC_WRAPPED_KEY_BYTES + sealed_len;
    uint8_t* msg = (uint8_t*)malloc(msg_len);
    if (!msg) { fprintf(stderr, "oom\n"); return 1; }
    memcpy(msg, wrapped, WBC_WRAPPED_KEY_BYTES);
    memcpy(msg + WBC_WRAPPED_KEY_BYTES, sealed, sealed_len);
    printf("message: %zu bytes = %d (wrapped key) + %zu (sealed payload)\n\n",
           msg_len, WBC_WRAPPED_KEY_BYTES, sealed_len);

    /* ---- READ ----------------------------------------------------------- */
    t0 = now_ms();
    uint8_t sk2[WBC_SESSION_KEY_BYTES];
    s = wbc_unwrap_key(ctx, msg, sk2);
    if (s != WBC_OK) { fprintf(stderr, "unwrap: %s\n", wbc_strerror(s)); return 1; }

    size_t opened_len = 0;
    s = wbc_bulk_open(sk2, msg + WBC_WRAPPED_KEY_BYTES, msg_len - WBC_WRAPPED_KEY_BYTES,
                      opened, &opened_len);
    if (s != WBC_OK) { fprintf(stderr, "bulk_open: %s\n", wbc_strerror(s)); return 1; }
    double t_read = now_ms() - t0;

    int ok = (opened_len == PAYLOAD_BYTES) && memcmp(payload, opened, PAYLOAD_BYTES) == 0;
    printf("READ\n");
    printf("  total                                  : %8.2f ms\n", t_read);
    printf("  round-trip                             : %s\n\n", ok ? "OK" : "FAIL");

    /* ---- tamper detection ------------------------------------------------
     * Run this BEFORE wiping sk2. Using a wiped (all-zero) key would make the
     * AEAD reject the payload for the wrong reason, and the check would pass
     * even with the bit-flip removed — i.e. assert nothing. */
    int tamper_ok = 1;
    {
        /* A flipped bit in the sealed payload must fail the tag. */
        msg[msg_len - 1] ^= 0x01;
        s = wbc_bulk_open(sk2, msg + WBC_WRAPPED_KEY_BYTES, msg_len - WBC_WRAPPED_KEY_BYTES,
                          opened, &opened_len);
        printf("tamper (payload): %s\n",
               s == WBC_ERR_AUTH ? "rejected (WBC_ERR_AUTH)" : "NOT DETECTED");
        if (s != WBC_ERR_AUTH) tamper_ok = 0;
        msg[msg_len - 1] ^= 0x01;

        /* A flipped bit in the WRAPPED KEY is caught too, indirectly: the wrap is
         * not separately authenticated, so it unwraps "successfully" to a wrong
         * key — and the AEAD then rejects the payload. That is why no second MAC
         * is needed on the wrap. */
        msg[WBC_BLOCK_BYTES] ^= 0x01;
        uint8_t bad_sk[WBC_SESSION_KEY_BYTES];
        s = wbc_unwrap_key(ctx, msg, bad_sk);
        if (s == WBC_OK) {
            s = wbc_bulk_open(bad_sk, msg + WBC_WRAPPED_KEY_BYTES,
                              msg_len - WBC_WRAPPED_KEY_BYTES, opened, &opened_len);
        }
        printf("tamper (wrapped key): %s\n",
               s == WBC_ERR_AUTH ? "rejected (WBC_ERR_AUTH)" : "NOT DETECTED");
        if (s != WBC_ERR_AUTH) tamper_ok = 0;
        wbc_wipe(bad_sk, sizeof bad_sk);
        msg[WBC_BLOCK_BYTES] ^= 0x01;
    }
    wbc_wipe(sk2, sizeof sk2);

    /* ---- the point ------------------------------------------------------- */
    printf("\nThe white-box cost above (%.2f ms) is TWO blocks and does not grow\n", t_wrap);
    printf("with the payload — wrap a 5 GiB payload's key and it is still %.2f ms.\n", t_wrap);
    printf("Only the AEAD line scales. There is deliberately no way to push the\n");
    printf("payload itself through the white-box: it would run at ~0.06 MB/s.\n");

    print_hex("\nwrapped session key: ", wrapped, WBC_WRAPPED_KEY_BYTES);
    printf("\nCAVEAT: between the unwrap and the wbc_wipe, the session key is an\n"
           "ordinary key in ordinary memory. The white-box protects the LONG-TERM\n"
           "key; it does not extend that guarantee to the session key or the bulk\n"
           "data. Keep its lifetime short and prefer a fresh key per message.\n");

    free(payload); free(sealed); free(opened); free(msg);
    wbc_close(ctx);
    wbc_free(blob);
    return (ok && tamper_ok) ? 0 : 1;
}
