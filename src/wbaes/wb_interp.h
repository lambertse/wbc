// wb_interp.h — plain C++ evaluator of a WhiteBox network.
//
// This is the reference the VM (milestone C) is differential-tested against:
// the VM must reproduce this exact sequence of table lookups and nibble XORs.
// At runtime the whole computation is *only* indexed table reads and XORs — no
// GF(2^8) math — which is the correctness anchor for the whole design.
#ifndef WBVM_WBAES_WB_INTERP_H
#define WBVM_WBAES_WB_INTERP_H

#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"

namespace wbaes {

// XOR two encoded bytes using a type-IV nibble table pair
// (xr[...][0]=hi plane, xr[...][1]=lo plane).
inline uint8_t XorEncoded(const std::array<XorTab, 2>& tabs, uint8_t a, uint8_t b) {
    uint8_t hi = tabs[0][((a >> 4) << 4) | (b >> 4)];
    uint8_t lo = tabs[1][((a & 0xF) << 4) | (b & 0xF)];
    return static_cast<uint8_t>((hi << 4) | lo);
}

// Encrypt one block through the white-box network.
Block WhiteBoxEncrypt(const WhiteBox& wb, const Block& in);

}  // namespace wbaes

#endif  // WBVM_WBAES_WB_INTERP_H
