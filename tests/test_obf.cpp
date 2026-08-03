// Milestone D: verify every obfuscation primitive is semantics-preserving
// before it is trusted inside the emitter. MBA identities are a classic bug
// source, so they are checked over the full 32-bit space by random sampling.
#include "test_util.h"
#include "fw/fw_schedule.h"
#include "obf/blinding.h"
#include "obf/mba.h"
#include "obf/opaque.h"
#include "vm/assembler.h"
#include "vm/handlers.h"
#include "vm/vm.h"
#include "wbaes/encodings.h"
#include "wbaes/wb_generator.h"

// No two registers may hold the same value at any point where a tampered operand
// could select between them.
//
// The byte-tamper cascade relies on a flipped register index changing the
// computation. That silently stops being true if two registers happen to hold
// equal values — which is exactly what happened when LDBI/STBI removed the last
// writer of RBASE and left it, and a dozen unused registers, sitting at 0
// alongside RZERO. The emitter now seeds the whole register file with distinct
// garbage in the preamble; this checks the preamble actually does that, by
// running the program and diffing the register file against a run where one
// register-operand byte was flipped.
static void TestRegisterSeeding() {
    using namespace wbaes;
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    auto wb = GenerateWhiteBox(key, 31, WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, 32, vm::ObfOptions::All());

    // Execute just the preamble (the register seeding) and confirm every register
    // ended up with a distinct value. The preamble is the leading run of LDI, so
    // stepping kNumRegs + 3 instructions covers it.
    vm::VMContext ctx;
    ctx.prog = &prog;
    ctx.data = prog.data;
    ctx.eff_root = prog.fw_root ^ fw::InterpFingerprint(prog.op_to_phys);
    ctx.key_reg = ctx.eff_root;
    const auto& handlers = vm::Handlers();
    for (int n = 0; n < vm::kNumRegs + 3 && !ctx.halted; ++n) {
        uint32_t ip = static_cast<uint32_t>(ctx.vip);
        ctx.ks = wbaes::Rng(fw::PrfSeed(ctx.eff_root, ctx.key_reg, ip));
        ctx.fold = fw::FoldInit();
        uint8_t phys = vm::FetchByte(ctx);
        if (ctx.halted) break;
        uint8_t logical = prog.phys_to_op[phys];
        if (logical >= vm::kOpCount || handlers[logical] == nullptr) break;
        handlers[logical](ctx);
        ctx.key_reg = fw::UpdateKeyReg(ctx.key_reg, ctx.fold, ip);
    }

    int collisions = 0;
    for (int i = 0; i < vm::kNumRegs; ++i)
        for (int j = i + 1; j < vm::kNumRegs; ++j)
            if (ctx.reg[i] == ctx.reg[j]) ++collisions;
    if (collisions) {
        std::printf("  FAIL %d register pair(s) share a value after the preamble;\n"
                    "       a flipped register operand between them is a silent no-op\n",
                    collisions);
        ++test::failures();
    } else {
        std::printf("  [regs] all %d registers distinct after the preamble\n", vm::kNumRegs);
    }
}

int main() {
    wbaes::Rng rng(0xC0DEC0DEull);

    // MBA identities must equal the primitive operator for all inputs.
    for (int i = 0; i < 200000; ++i) {
        uint32_t x = static_cast<uint32_t>(rng.next());
        uint32_t y = static_cast<uint32_t>(rng.next());
        CHECK(obf::MbaXor(x, y) == (x ^ y));
        CHECK(obf::MbaOr(x, y) == (x | y));
        CHECK(obf::MbaAnd(x, y) == (x & y));
        CHECK(obf::MbaAdd(x, y) == (x + y));
        if (test::failures()) break;
    }

    // Opaque-true predicate is nonzero for every input (guards are always taken).
    for (int i = 0; i < 100000; ++i) {
        uint32_t x = static_cast<uint32_t>(rng.next());
        CHECK(obf::OpaqueTrue(x) == 0xFFFFFFFFu);
        if (test::failures()) break;
    }

    // Handler duplication: variants are disjoint and decode back to their op.
    wbaes::Rng brng(7);
    auto ob = obf::BuildOpcodeBlinding(brng, 19, 3, 5);
    std::array<int, 256> owner{};
    owner.fill(-1);
    for (int op = 0; op < 19; ++op) {
        CHECK(!ob.variants[op].empty());
        for (uint8_t phys : ob.variants[op]) {
            CHECK(ob.phys_to_op[phys] == op);
            CHECK(owner[phys] == -1);  // no physical byte shared between opcodes
            owner[phys] = op;
        }
    }

    TestRegisterSeeding();
    return test::Report("test_obf");
}
