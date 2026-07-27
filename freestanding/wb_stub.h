/* wb_stub.h — freestanding white-box AES-128 runtime for a device stub.
 *
 * Drop-in for a no-libc environment such as native-lib-encryption's `stub/`:
 *   - no libc, no malloc, no globals, no function pointers (relocation-free);
 *   - only integer ops, small fixed stack arrays, and table lookups + XOR;
 *   - operates on a table image produced by wbc_export_tables / wb_keygen
 *     --export-tables (layout in wb_table_layout.h).
 *
 * The device runs the table network *directly* (no VM bytecode/dispatcher — that
 * needs mutable memory). The security property carried onto the device is that
 * the AES key is diffused across these tables and never appears as raw bytes.
 *
 * Header-only: `#include "wb_stub.h"` in one place and call the functions.
 * Compiles clean with -ffreestanding -fno-builtin -nostdlib.
 */
#ifndef WB_STUB_H
#define WB_STUB_H

#include "wb_table_layout.h"

/* ShiftRows source position for destination `dst` (state is column-major). */
static inline int wbstub__sr_src(int dst) {
    int r = dst & 3;
    int c = dst >> 2;
    return r + 4 * ((c + r) & 3);
}

/* XOR two encoded bytes via a type-IV nibble table pair (hi/lo planes). */
static inline uint8_t wbstub__xor(const uint8_t* hi, const uint8_t* lo,
                                  uint8_t a, uint8_t b) {
    uint8_t h = hi[(uint8_t)(((a >> 4) << 4) | (b >> 4))];
    uint8_t l = lo[(uint8_t)(((a & 0xF) << 4) | (b & 0xF))];
    return (uint8_t)((h << 4) | l);
}

/* Encrypt one 16-byte block. `in` and `out` may alias. `tables` -> image base. */
static inline void wbstub_encrypt_block(const uint8_t* tables,
                                        const uint8_t in[16], uint8_t out[16]) {
    const uint8_t* T = tables;
    uint8_t state[16], t[16], o[16];
    int i, m, c, j, mm, dst;

    for (i = 0; i < 16; ++i) state[i] = in[i];

    for (m = 0; m < 9; ++m) {
        /* T-box layer -> t[] */
        for (i = 0; i < 16; ++i) t[i] = WB_TBOX_ROW(T, m, i)[state[i]];

        /* ShiftRows routing + Tyi + type-IV XOR tree, per column */
        for (c = 0; c < 4; ++c) {
            uint8_t ty[4][4];
            for (mm = 0; mm < 4; ++mm) {
                int p = 4 * c + mm;
                uint8_t tv = t[wbstub__sr_src(p)];
                const uint8_t* row = WB_TY_ROW(T, m, p);
                ty[mm][0] = row[(size_t)tv * 4 + 0];
                ty[mm][1] = row[(size_t)tv * 4 + 1];
                ty[mm][2] = row[(size_t)tv * 4 + 2];
                ty[mm][3] = row[(size_t)tv * 4 + 3];
            }
            for (j = 0; j < 4; ++j) {
                uint8_t s = wbstub__xor(WB_XR_ROW(T, m, c, j, 0, 0),
                                        WB_XR_ROW(T, m, c, j, 0, 1),
                                        ty[0][j], ty[1][j]);
                s = wbstub__xor(WB_XR_ROW(T, m, c, j, 1, 0),
                                WB_XR_ROW(T, m, c, j, 1, 1), s, ty[2][j]);
                s = wbstub__xor(WB_XR_ROW(T, m, c, j, 2, 0),
                                WB_XR_ROW(T, m, c, j, 2, 1), s, ty[3][j]);
                o[4 * c + j] = s;
            }
        }
        for (i = 0; i < 16; ++i) state[i] = o[i];
    }

    /* Final round: T-box (k9,k10 folded), then ShiftRows into the output. */
    for (i = 0; i < 16; ++i) t[i] = WB_TBOX_ROW(T, 9, i)[state[i]];
    for (dst = 0; dst < 16; ++dst) out[dst] = t[wbstub__sr_src(dst)];
}

/* CTR mode: encrypts OR decrypts `len` bytes in place-capable fashion.
 * `iv` is the initial 16-byte counter (incremented big-endian per block).
 * Uses only block-encryption, so it provides decryption too. */
static inline void wbstub_ctr_xcrypt(const uint8_t* tables, const uint8_t iv[16],
                                     const uint8_t* in, uint8_t* out,
                                     uint32_t len) {
    uint8_t counter[16], ks[16];
    uint32_t off = 0;
    int i, k;
    for (i = 0; i < 16; ++i) counter[i] = iv[i];
    while (off < len) {
        wbstub_encrypt_block(tables, counter, ks);
        uint32_t n = (len - off < 16u) ? (len - off) : 16u;
        for (k = 0; (uint32_t)k < n; ++k) out[off + k] = in[off + k] ^ ks[k];
        off += n;
        for (i = 15; i >= 0; --i) {           /* big-endian increment */
            if ((uint8_t)(++counter[i]) != 0) break;
        }
    }
}

#endif /* WB_STUB_H */
