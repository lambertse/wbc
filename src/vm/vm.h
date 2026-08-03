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
#include <cstddef>
#include <cstdint>
#include <vector>

#include "fw/fw_schedule.h"    // fw::FoldByte: instruction checksum, folded on fetch
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
//
// These are DELIBERATELY defined here rather than in vm.cpp, for two reasons:
//
//  * Resistance. Out-of-line, FetchByte is a single chokepoint: one breakpoint
//    or PLT hook on it dumps every plaintext bytecode byte of the program, in
//    execution order, with no other work. Inlined into all 19 handlers plus the
//    dispatcher, that single point disappears and each copy is obfuscated
//    independently by the per-function O-MVLL passes.
//  * Speed. A block fetches ~58k bytes, each a separate cross-TU call from
//    handlers.cpp (no LTO in either build path), wrapping ~10 cycles of actual
//    work. The call overhead is a significant fraction of the total.
//
// Keep them header-inline; do not move them back.
//
// `inline` alone is NOT sufficient for the resistance argument: it permits but
// does not require inlining, and clang emits a weak out-of-line copy at any call
// site it declines to inline — which puts the chokepoint symbol straight back
// into the archive (verified: a plain-`inline` build still shipped
// .text._ZN2vm10FetchImm32ERNS_9VMContextE). always_inline is what actually
// removes it. Both functions are ~10 instructions, so the code growth is small.
// Escape hatch: always_inline is a hard ERROR (not a hint) if a transform
// prevents inlining, and O-MVLL's passes run over exactly these functions. If an
// obfuscated build ever fails with "always_inline function could not be
// inlined", build with -DWBVM_NO_FORCE_INLINE to fall back to plain `inline`.
// That costs the chokepoint property described above — check with
// `nm libwbcrypto.a | grep FetchByte` and re-target omvll_config.py instead if
// you can.
#if (defined(__GNUC__) || defined(__clang__)) && !defined(WBVM_NO_FORCE_INLINE)
#define WBVM_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define WBVM_ALWAYS_INLINE inline
#endif

WBVM_ALWAYS_INLINE uint8_t FetchByte(VMContext& ctx) {
    const Program& p = *ctx.prog;
    if (ctx.vip >= p.code.size()) {
        ctx.halted = true;
        return 0;
    }
    // Context-keyed decode: XOR with the current instruction's keystream, then
    // fold the decoded byte so any tamper diverges the evolving key.
    uint8_t ksb = static_cast<uint8_t>(ctx.ks.next() & 0xFF);
    uint8_t b = static_cast<uint8_t>(p.code[ctx.vip] ^ ksb);
    ctx.fold = fw::FoldByte(ctx.fold, b);
    ++ctx.vip;
    return b;
}

WBVM_ALWAYS_INLINE uint32_t FetchImm32(VMContext& ctx) {
    uint32_t v = 0;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 0;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 8;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 16;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 24;
    return v;
}

// Run `prog` on a 16-byte block: writes block into DATA, executes, reads it back.
// Returns the resulting 16 bytes.
//
// PERFORMANCE NOTE — do not "optimize" the per-block DATA copy away.
// Run copies the whole ~400 KB DATA image per call, though only the trailing 48
// bytes (STATE/TMP/OUT) are ever written, so it looks like obvious waste. It is
// not: restoring the read-only table bank every block is what washes out an injected
// fault before the next block can observe it, which is the defence against
// differential fault analysis (a practical published attack on Chow-style
// white-boxes). Two alternatives were implemented and measured against this:
//   * reuse the buffer and VERIFY it per block instead of restoring — ~39%
//     SLOWER, because streaming both images through cache evicts the table bank
//     and the next block's ~3k scattered lookups then miss to DRAM; and it is a
//     weaker guarantee (detect after the fact rather than prevent);
//   * reuse the buffer and keep restoring, saving only the allocation — no
//     measurable gain at all, since the copy dominates and the allocator was
//     already recycling the same block.
// The copy is ~3% of Run (`data_copy` in wb_bench proves it). Leave it alone.
std::array<uint8_t, 16> Run(const Program& prog, const std::array<uint8_t, 16>& in);

}  // namespace vm

#endif  // WBVM_VM_VM_H
