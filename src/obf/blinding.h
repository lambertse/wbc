// blinding.h — handler duplication / opcode blinding (Blazytko deck,
// "handle_vadd' / handle_vadd''": several handlers with identical semantics).
//
// Each logical opcode is assigned SEVERAL physical byte values; the dispatcher
// maps all of them back to the same handler, and the assembler picks a random
// physical byte every time it emits that opcode. A static analyst can no longer
// assume "one byte = one operation": the same operation appears under many
// opcodes and the opcode histogram is flattened.
#ifndef WBVM_OBF_BLINDING_H
#define WBVM_OBF_BLINDING_H

#include <array>
#include <cstdint>
#include <vector>

#include "wbaes/encodings.h"  // wbaes::Rng

namespace obf {

struct OpcodeBlinding {
    // variants[op] = the physical bytes that all decode to logical opcode `op`.
    std::vector<std::vector<uint8_t>> variants;
    std::array<uint8_t, 256> phys_to_op{};  // physical byte -> logical op (0xFF = invalid)
    std::array<uint8_t, 256> op_to_phys{};  // logical op -> a primary physical byte
};

// Assign each of `op_count` logical opcodes between `min_variants` and
// `max_variants` distinct physical bytes, drawn without collision from a seeded
// permutation of 0..255.
OpcodeBlinding BuildOpcodeBlinding(wbaes::Rng& rng, int op_count,
                                   int min_variants, int max_variants);

}  // namespace obf

#endif  // WBVM_OBF_BLINDING_H
