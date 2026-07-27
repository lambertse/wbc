#include "gf256.h"

namespace wbaes {
namespace gf {

uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        b >>= 1;
        a = xtime(a);
    }
    return result;
}

uint8_t inv(uint8_t a) {
    // a^254 == a^-1 in GF(2^8) (since a^255 == 1 for a != 0). 0 -> 0.
    if (a == 0) return 0;
    uint8_t result = 1;
    uint8_t base = a;
    for (int e = 0; e < 254; ++e) result = mul(result, base);
    // The loop above computes a^254 by repeated multiplication.
    return result;
}

}  // namespace gf
}  // namespace wbaes
