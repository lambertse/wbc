#include "aes_tables.h"

#include "gf256.h"

namespace wbaes {

// MixColumns matrix M (circulant of {02,03,01,01}).
//   [02 03 01 01]
//   [01 02 03 01]
//   [01 01 02 03]
//   [03 01 01 02]
// Column `col` of M scaled by input byte x gives that byte's contribution.
std::array<uint8_t, 4> Tyi(int col, uint8_t x) {
    static const uint8_t M[4][4] = {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2},
    };
    std::array<uint8_t, 4> out{};
    for (int row = 0; row < 4; ++row) {
        out[row] = gf::mul(M[row][col], x);
    }
    return out;
}

}  // namespace wbaes
