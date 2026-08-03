/* keywrap.c — the pattern to use for anything bigger than a few hundred bytes.
 *
 * The white-box runs well under 1 MB/s: every 16-byte block is ~13k obfuscated
 * VM instructions, so a 5 MiB payload pushed through wbc_crypt_ctr takes over
 * two minutes per leg. That is inherent to the construction, not a bug to be
 * optimized away — the slowness IS the obfuscation.
 *
 * So don't push data through it. Push a KEY through it:
 *
 *     white-box  ──wraps──▶  32-byte session key   (2 blocks, ~1 ms)
 *     session key ──seals──▶ the actual payload    (conventional AEAD, GB/s)
 *
 * The long-term key still never exists in memory. What you give up is that the
 * SESSION key does: see the caveat printed at the end and documented in
 * include/wbcrypto.h.
 *
 * This demo links libwbprovision because it seals its own blob for
 * self-containment. A field app links only libwbcrypto and calls wbc_open.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wbcrypto.h"

#define PAYLOAD_BYTES (1u << 20) /* 1 MiB */

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

int main(void) {
    const uint8_t long_term_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const char* pass = "keywrap-demo";
    wbc_status s;

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

    printf("payload: %u bytes\n\n", PAYLOAD_BYTES);

    /* ---- WRITE ---------------------------------------------------------- */
    double t0 = now_ms();

    uint8_t sk[WBC_SESSION_KEY_BYTES];
    s = wbc_random(sk, sizeof sk);
    if (s != WBC_OK) { fprintf(stderr, "random: %s\n", wbc_strerror(s)); return 1; }

    /* The white-box wraps the session key: 32 bytes = 2 VM blocks. The IV must
     * be unique per wrap under this long-term key — CTR with a repeated IV
     * reuses keystream, which would leak the XOR of two session keys. Store it
     * next to the wrapped key; it is not secret. */
    uint8_t wrap_iv[WBC_BLOCK_BYTES], wrapped_sk[WBC_SESSION_KEY_BYTES];
    s = wbc_random(wrap_iv, sizeof wrap_iv);
    if (s != WBC_OK) { fprintf(stderr, "random: %s\n", wbc_strerror(s)); return 1; }

    double t_wrap0 = now_ms();
    s = wbc_crypt_ctr(ctx, wrap_iv, sk, wrapped_sk, sizeof sk);
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
    printf("  total                                  : %8.2f ms  -> %zu bytes\n\n",
           t_write, sealed_len);

    /* On disk/wire you store: wrap_iv || wrapped_sk || sealed. */

    /* ---- READ ----------------------------------------------------------- */
    t0 = now_ms();
    uint8_t sk2[WBC_SESSION_KEY_BYTES];
    /* CTR is its own inverse, so unwrapping is the same call. */
    s = wbc_crypt_ctr(ctx, wrap_iv, wrapped_sk, sk2, sizeof sk2);
    if (s != WBC_OK) { fprintf(stderr, "unwrap: %s\n", wbc_strerror(s)); return 1; }

    size_t opened_len = 0;
    s = wbc_bulk_open(sk2, sealed, sealed_len, opened, &opened_len);
    if (s != WBC_OK) { fprintf(stderr, "bulk_open: %s\n", wbc_strerror(s)); return 1; }
    wbc_wipe(sk2, sizeof sk2);
    double t_read = now_ms() - t0;

    int ok = (opened_len == PAYLOAD_BYTES) && memcmp(payload, opened, PAYLOAD_BYTES) == 0;
    printf("READ\n");
    printf("  total                                  : %8.2f ms\n", t_read);
    printf("  round-trip                             : %s\n\n", ok ? "OK" : "FAIL");

    /* A forged tag must be rejected rather than returning garbage. */
    sealed[sealed_len - 1] ^= 0x01;
    s = wbc_bulk_open(sk2, sealed, sealed_len, opened, &opened_len);
    printf("tamper detection: %s\n", s == WBC_ERR_AUTH ? "rejected (WBC_ERR_AUTH)" : "NOT DETECTED");
    sealed[sealed_len - 1] ^= 0x01;

    /* ---- the comparison this example exists to make ---------------------- */
    double per_block_ms = t_wrap / 2.0; /* 32 bytes = 2 white-box blocks */
    double direct_ms = per_block_ms * ((double)PAYLOAD_BYTES / WBC_BLOCK_BYTES);
    printf("\nSame payload straight through wbc_crypt_ctr would take about"
           " %.0f s per leg\n", direct_ms / 1000.0);
    printf("(extrapolated from the measured wrap: %.3f ms per 16-byte block).\n",
           per_block_ms);
    printf("Key wrapping is ~%.0fx faster here and protects the same long-term key.\n",
           direct_ms / (t_write > 0.001 ? t_write : 0.001));

    print_hex("\nwrapped session key: ", wrapped_sk, sizeof wrapped_sk);
    printf("\nCAVEAT: between the unwrap and the wbc_wipe, the session key is an\n"
           "ordinary key in ordinary memory. The white-box protects the LONG-TERM\n"
           "key; it does not extend that guarantee to the session key or the bulk\n"
           "data. Keep its lifetime short and prefer a fresh key per message.\n");

    free(payload); free(sealed); free(opened);
    wbc_close(ctx);
    wbc_free(blob);
    return ok ? 0 : 1;
}
