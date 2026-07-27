// gf256.h — GF(2^8) arithmetic over the AES field (irreducible poly 0x11B).
//
// Used ONLY at table-build / reference time. The runtime white-box does no
// field math: every multiplication is baked into a lookup table offline
// (see aes_tables.*). Keeping the field code here documents that boundary.
#ifndef WBVM_WBAES_GF256_H
#define WBVM_WBAES_GF256_H

#include <cstdint>

namespace wbaes {
namespace gf {

// Multiply by x (i.e. by 2) in GF(2^8), reducing mod 0x11B.
inline uint8_t xtime(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

// General GF(2^8) multiplication via Russian-peasant / carryless multiply.
uint8_t mul(uint8_t a, uint8_t b);

// Multiplicative inverse in GF(2^8) (0 maps to 0). Basis of the AES S-box.
uint8_t inv(uint8_t a);

}  // namespace gf
}  // namespace wbaes

#endif  // WBVM_WBAES_GF256_H
