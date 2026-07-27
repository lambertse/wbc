// assembler.h — compile a WhiteBox network into a VM Program.
//
// Lays the entire table bank into DATA memory, then emits generic VM bytecode
// (table loads + shifts/ors + XOR-table lookups) that reproduces
// WhiteBoxEncrypt step for step. The emitted opcodes are remapped through a
// seeded permutation and the byte stream is keystream-encoded, so the compiled
// program is opaque to static disassembly.
#ifndef WBVM_VM_ASSEMBLER_H
#define WBVM_VM_ASSEMBLER_H

#include <cstdint>

#include "vm/vm.h"
#include "wbaes/wb_generator.h"

namespace vm {

// Which bytecode obfuscation layers to apply when compiling.
struct ObfOptions {
    bool handler_duplication = true;  // several physical opcodes per handler
    bool mba = true;                  // MBA-rewrite emitted index arithmetic
    bool opaque_predicates = true;    // insert always-taken guards + junk blocks

    static ObfOptions None() { return {false, false, false}; }
    static ObfOptions All() { return {true, true, true}; }
};

// Compile `wb` into a Program. `seed` drives the opcode blinding, the bytecode
// keystream and the randomized obfuscation choices (independent from the
// white-box encoding seed).
Program AssembleWhiteBox(const wbaes::WhiteBox& wb, uint64_t seed,
                         ObfOptions obf = ObfOptions::All());

}  // namespace vm

#endif  // WBVM_VM_ASSEMBLER_H
