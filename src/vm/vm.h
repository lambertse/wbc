// vm.h — the obfuscation VM: context, program image, and the FDE dispatcher.
//
// Design goals (per project requirements):
//  * Real-VM structure: separate CODE, DATA and STACK memories (Harvard-style),
//    a register file and a virtual instruction pointer — no shared flat buffer.
//  * Hard to statically investigate: the bytecode is decoded with a CONTEXT-KEYED
//    schedule (fw_schedule.h) that evolves with execution — there is no stored
//    keystream, and tampering any code byte (or the opcode map) cascades into
//    garbage. Decoding happens only during fetch.
#ifndef WBVM_VM_VM_H
#define WBVM_VM_VM_H

#include <array>
#include <cstdint>
#include <vector>

#include "vm/isa.h"
#include "wbaes/encodings.h"  // wbaes::Rng: per-instruction keystream generator

namespace vm {

// A compiled program: encoded code memory + the opcode permutation + the initial
// data-memory image + the firmware root key. Serialized into the trusted-storage
// blob. No keystream is stored — decode is regenerated from fw_root + the
// interpreter fingerprint + execution feedback.
struct Program {
    std::vector<uint8_t> code;              // context-encrypted bytecode
    uint64_t fw_root = 0;                    // root key for the decode schedule
    std::array<uint8_t, 256> op_to_phys{};  // logical Op -> physical byte
    std::array<uint8_t, 256> phys_to_op{};  // physical byte -> logical Op

    std::vector<uint8_t> data;  // initial DATA memory (table bank + I/O area)
    uint32_t block_off = 0;     // offset of the 16-byte block (input and output)
};

// Live execution state. CODE lives in prog; DATA and STACK are private and
// mutable per run.
struct VMContext {
    const Program* prog = nullptr;
    std::vector<uint8_t> data;       // working DATA memory (copy of prog->data)
    std::array<uint32_t, kNumRegs> reg{};
    std::vector<uint32_t> stack;     // separate STACK memory
    size_t vip = 0;                  // virtual instruction pointer into CODE
    bool halted = false;
    uint64_t steps = 0;              // executed-instruction counter (guards runaway)

    // Context-keyed decode state (fw_schedule.h).
    uint64_t eff_root = 0;           // fw_root ^ interpreter fingerprint
    uint64_t key_reg = 0;            // evolves per executed instruction
    wbaes::Rng ks{0};                // keystream for the current instruction
    uint32_t fold = 0;               // running checksum of the current instruction
};

// Decode-on-fetch primitives used by the dispatcher and handlers.
uint8_t FetchByte(VMContext& ctx);      // next decoded code byte
uint32_t FetchImm32(VMContext& ctx);    // next decoded 32-bit little-endian immediate

// Run `prog` on a 16-byte block: writes block into DATA, executes, reads it back.
// Returns the resulting 16 bytes.
std::array<uint8_t, 16> Run(const Program& prog, const std::array<uint8_t, 16>& in);

}  // namespace vm

#endif  // WBVM_VM_VM_H
