#include "vm/vm.h"

#include "fw/fw_schedule.h"
#include "vm/handlers.h"

namespace vm {

uint8_t FetchByte(VMContext& ctx) {
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

uint32_t FetchImm32(VMContext& ctx) {
    uint32_t v = 0;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 0;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 8;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 16;
    v |= static_cast<uint32_t>(FetchByte(ctx)) << 24;
    return v;
}

std::array<uint8_t, 16> Run(const Program& prog, const std::array<uint8_t, 16>& in) {
    VMContext ctx;
    ctx.prog = &prog;
    ctx.data = prog.data;            // private working copy of DATA memory
    ctx.stack.reserve(64);
    ctx.vip = 0;

    // Bind decode to the interpreter fingerprint; seed the evolving key.
    ctx.eff_root = prog.fw_root ^ fw::InterpFingerprint(prog.op_to_phys);
    ctx.key_reg = ctx.eff_root;

    // Load the input block into DATA at the agreed offset.
    for (int i = 0; i < 16; ++i) ctx.data[prog.block_off + i] = in[i];

    const auto& handlers = Handlers();
    const uint64_t kStepLimit = 100'000'000;  // guard against malformed programs

    // Fetch-decode-execute dispatcher, one instruction per iteration.
    while (!ctx.halted && ctx.steps < kStepLimit) {
        uint32_t ip = static_cast<uint32_t>(ctx.vip);
        // Fresh per-instruction keystream + fold, keyed by the evolving key_reg.
        ctx.ks = wbaes::Rng(fw::PrfSeed(ctx.eff_root, ctx.key_reg, ip));
        ctx.fold = fw::FoldInit();

        uint8_t phys = FetchByte(ctx);
        if (ctx.halted) break;
        uint8_t logical = prog.phys_to_op[phys];
        if (logical >= kOpCount || handlers[logical] == nullptr) {
            ctx.halted = true;
            break;
        }
        handlers[logical](ctx);
        // Evolve the key with this instruction's decoded bytes + position.
        ctx.key_reg = fw::UpdateKeyReg(ctx.key_reg, ctx.fold, ip);
        ++ctx.steps;
    }

    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16; ++i) out[i] = ctx.data[prog.block_off + i];
    return out;
}

}  // namespace vm
