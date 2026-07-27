// wb_generator.h — compile an AES-128 key into a Chow white-box table network.
//
// This is the "trusted storage" producer: the key is consumed here and never
// stored as bytes again — it survives only diffused into the T-boxes (mixed
// with the S-box) and, at the final round, into the folded k10 output.
//
// Strata (WBLevel), each of which must still compute plain AES so bugs localise:
//   Naked    - T-boxes + Tyi + type-IV XOR tables, all encodings identity.
//   Internal - random 4-bit input/output encodings on every table (they cancel).
//              This is the level shipped in the sealed blob.
// (Roadmap, deliberately NOT an enum value so callers can't select something
//  that silently aliases Internal: a further "Mixing" stratum would add 32-bit
//  linear mixing bijections per column, inverted into the next round.)
#ifndef WBVM_WBAES_WB_GENERATOR_H
#define WBVM_WBAES_WB_GENERATOR_H

#include <array>
#include <cstdint>
#include <memory>

#include "wbaes/aes_ref.h"

namespace wbaes {

enum class WBLevel { Naked, Internal };

using Table256 = std::array<uint8_t, 256>;              // encoded byte -> encoded byte
using TyTable = std::array<std::array<uint8_t, 4>, 256>;  // encoded byte -> 4 encoded bytes
using XorTab = std::array<uint8_t, 256>;                 // (nibA<<4|nibB) -> nibble

// The full white-box network. ~1.5 MB, so always heap-allocate.
struct WhiteBox {
    WBLevel level;
    // T-boxes for AES rounds 1..10 (indices 0..9), one per state byte.
    std::array<std::array<Table256, 16>, 10> tbox;
    // Tyi tables for rounds 1..9 (indices 0..8), post-ShiftRows position 0..15.
    std::array<std::array<TyTable, 16>, 9> ty;
    // Type-IV nibble XOR tables to fold each column's four Tyi outputs together.
    // [round 0..8][column 0..3][lane 0..3][tree step 0..2][0=hi nibble,1=lo nibble]
    std::array<std::array<std::array<std::array<std::array<XorTab, 2>, 3>, 4>, 4>, 9> xr;
};

// Build the white-box for `key`, using `seed` to derive the internal encodings.
std::unique_ptr<WhiteBox> GenerateWhiteBox(const Key128& key, uint64_t seed,
                                           WBLevel level);

}  // namespace wbaes

#endif  // WBVM_WBAES_WB_GENERATOR_H
