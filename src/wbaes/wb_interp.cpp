#include "wbaes/wb_interp.h"

#include "wbaes/aes_tables.h"

namespace wbaes {

Block WhiteBoxEncrypt(const WhiteBox& wb, const Block& in) {
    std::array<uint8_t, 16> state = in;  // external input encoding = identity

    for (int m = 0; m < 9; ++m) {
        // T-box layer.
        std::array<uint8_t, 16> t{};
        for (int i = 0; i < 16; ++i) t[i] = wb.tbox[m][i][state[i]];

        // ShiftRows routing + Tyi + type-IV XOR tree, per column.
        std::array<uint8_t, 16> out{};
        for (int c = 0; c < 4; ++c) {
            // Gather the four post-ShiftRows Tyi outputs feeding column c.
            std::array<std::array<uint8_t, 4>, 4> ty{};
            for (int mm = 0; mm < 4; ++mm) {
                int p = 4 * c + mm;
                uint8_t src_byte = t[ShiftRowsSrc(p)];
                ty[mm] = wb.ty[m][p][src_byte];
            }
            for (int j = 0; j < 4; ++j) {
                uint8_t s = XorEncoded(wb.xr[m][c][j][0], ty[0][j], ty[1][j]);
                s = XorEncoded(wb.xr[m][c][j][1], s, ty[2][j]);
                s = XorEncoded(wb.xr[m][c][j][2], s, ty[3][j]);
                out[4 * c + j] = s;
            }
        }
        state = out;
    }

    // Final round (index 9): T-box (k9 folded in, k10 folded past ShiftRows).
    std::array<uint8_t, 16> t{};
    for (int i = 0; i < 16; ++i) t[i] = wb.tbox[9][i][state[i]];
    Block ct{};
    for (int dst = 0; dst < 16; ++dst) ct[dst] = t[ShiftRowsSrc(dst)];
    return ct;
}

}  // namespace wbaes
