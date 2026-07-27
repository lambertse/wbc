// fw_schedule.h — the context-keyed firmware decode schedule.
//
// SINGLE SOURCE OF TRUTH shared by the firmware encryptor (src/fw/fwcrypt.cpp)
// and the CPU decode (src/vm/vm.cpp). Both sides must evolve the key identically,
// so all the arithmetic lives here as inline/constexpr with no other deps.
//
// Model: each executed instruction at code offset `ip` is XOR-decoded with a
// fresh keystream seeded by PrfSeed(root, key_reg, ip). After the instruction,
// key_reg folds in a checksum of the instruction's (decoded) bytes + ip, so the
// key EVOLVES with execution and any byte tamper cascades into every later
// instruction. `root` itself is bound to the interpreter fingerprint, so
// tampering the opcode map / handler identity breaks all decode.
#ifndef WBVM_FW_FW_SCHEDULE_H
#define WBVM_FW_FW_SCHEDULE_H

#include <array>
#include <cstdint>

#include "vm/isa.h"

namespace fw {

inline uint64_t Splitmix(uint64_t z) {
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Per-instruction keystream seed.
inline uint64_t PrfSeed(uint64_t root, uint64_t key_reg, uint32_t ip) {
    return Splitmix(root ^ key_reg ^ (0xD1B54A32D192ED03ULL * (ip + 1)));
}

// Rolling fold over an instruction's bytes (FNV-1a on 32 bits).
inline uint32_t FoldInit() { return 2166136261u; }
inline uint32_t FoldByte(uint32_t f, uint8_t b) { return (f ^ b) * 16777619u; }

// key_reg update applied after each executed instruction.
inline uint64_t UpdateKeyReg(uint64_t key_reg, uint32_t fold, uint32_t ip) {
    return Splitmix(key_reg ^ (static_cast<uint64_t>(fold) << 1) ^
                    (0x9E3779B97F4A7C15ULL * (ip + 1)));
}

// A fixed per-opcode identity constant standing in for each handler's identity.
// The interpreter fingerprint hashes this together with the live opcode map, so
// re-mapping opcodes or patching this table changes `root` and breaks decode.
// (Binding to actual handler machine code is possible but platform-specific;
//  documented as future work in docs/THREATMODEL.md.)
inline constexpr std::array<uint8_t, vm::kOpCount> kInterpFingerprint = {
    0x3B, 0x9A, 0xC4, 0x17, 0x52, 0xE8, 0x0D, 0x71, 0xBF, 0x2A,
    0x66, 0xD3, 0x48, 0x95, 0xFC, 0x81, 0x2E, 0x57, 0xA9,
};

// Bind decode to the interpreter: hash the fixed fingerprint + the live opcode
// permutation into a 64-bit value folded into the root at open time.
inline uint64_t InterpFingerprint(const std::array<uint8_t, 256>& op_to_phys) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < vm::kOpCount; ++i)
        h = (h ^ kInterpFingerprint[i]) * 1099511628211ULL;
    for (int i = 0; i < vm::kOpCount; ++i)
        h = (h ^ op_to_phys[i]) * 1099511628211ULL;
    return Splitmix(h);
}

// Root key derived from the program seed (fingerprint folded in separately).
inline uint64_t DeriveRoot(uint64_t seed) {
    return Splitmix(seed ^ 0xF12E9A7C51D3B6E1ULL);
}

}  // namespace fw

#endif  // WBVM_FW_FW_SCHEDULE_H
