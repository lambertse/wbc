#include "vm/vm.h"

#include "fw/fw_schedule.h"
#include "vm/handlers.h"

namespace vm {

// FetchByte / FetchImm32 are header-inline in vm.h — see the comment there for
// why (they are both the hot path and the single most useful hook point).

std::array<uint8_t, 16> Run(const Program& prog, const std::array<uint8_t, 16>& in) {
    VMContext ctx;
    ctx.prog = &prog;
    // Private working copy of DATA memory. Also the anti-DFA reset — see the
    // note on Run() in vm.h before considering hoisting this out of the loop.
    ctx.data = prog.data;
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
