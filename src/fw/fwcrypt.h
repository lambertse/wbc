// fwcrypt.h — the separate firmware-encryption toolchain.
//
// Consumes the assembler's *plaintext* bytecode (with instruction spans and the
// dead junk ranges) and produces the final encrypted Program whose bytecode is
// decodable only by evolving the context key in lock-step with execution
// (fw_schedule.h). This is the clean split the design calls for: the assembler
// lays out instructions, this toolchain encrypts the "firmware".
#ifndef WBVM_FW_FWCRYPT_H
#define WBVM_FW_FWCRYPT_H

#include <array>
#include <cstdint>
#include <utility>
#include <vector>

#include "vm/vm.h"

namespace fw {

// Plaintext program handed over by the assembler.
struct AssembledProgram {
    std::vector<uint8_t> plain;  // plaintext bytecode
    // (offset,len) of every instruction, in address order (== execution order
    // once junk is skipped, since guards jump forward over their junk blocks).
    std::vector<std::pair<uint32_t, uint32_t>> spans;
    // [start,end) byte ranges that are never executed (opaque-guard junk).
    std::vector<std::pair<uint32_t, uint32_t>> junk_ranges;
    std::array<uint8_t, 256> op_to_phys{};
    std::array<uint8_t, 256> phys_to_op{};
    std::vector<uint8_t> data;
    uint32_t block_off = 0;
};

// Encrypt `asm_prog` into a runnable Program. `seed` derives the root key;
// the interpreter fingerprint is folded in at run time (never stored).
vm::Program EncryptFirmware(const AssembledProgram& asm_prog, uint64_t seed);

}  // namespace fw

#endif  // WBVM_FW_FWCRYPT_H
