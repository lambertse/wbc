// aes_tables.h — AES-specific pieces the white-box network is built from.
//
// These are the "naked" mathematical ingredients (no encodings): the ShiftRows
// wire permutation and the Tyi decomposition of MixColumns. wb_generator folds
// key material and encodings around them.
#ifndef WBVM_WBAES_AES_TABLES_H
#define WBVM_WBAES_AES_TABLES_H

#include <array>
#include <cstdint>

namespace wbaes {

// State is column-major: index = row + 4*col. ShiftRows sends the byte that
// ends up at position `dst` from source position ShiftRowsSrc(dst).
inline int ShiftRowsSrc(int dst) {
    int r = dst % 4;
    int c = dst / 4;
    return r + 4 * ((c + r) % 4);
}

// Tyi(col, x): the contribution of input byte x, sitting in matrix row `col`
// (0..3) of a MixColumns column, to the 4 output bytes of that column. Returns
// the 4 bytes {o0,o1,o2,o3}. Summing (XOR) Tyi(0,a0..) .. Tyi(3,a3..) yields the
// MixColumns of the column (a0,a1,a2,a3).
std::array<uint8_t, 4> Tyi(int col, uint8_t x);

}  // namespace wbaes

#endif  // WBVM_WBAES_AES_TABLES_H
