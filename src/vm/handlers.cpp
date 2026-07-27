#include "vm/handlers.h"

namespace vm {

namespace {

// Each handler is entered *after* its opcode byte has been fetched; it fetches
// its own operands via the decode-on-fetch stream.
//
// Register operands are fetched through Rf(), which MASKS the index into
// [0, kNumRegs). This matters for the context-keyed firmware: a tampered code
// byte cascades into garbage-decoded operands, and an unbounded register index
// would read/write out of bounds. Masking guarantees tampering yields *wrong
// output*, never a crash. (Shift amounts and jump targets are not masked.)
inline uint8_t Rf(VMContext& ctx) {
    return static_cast<uint8_t>(FetchByte(ctx) & (kNumRegs - 1));
}

void HHalt(VMContext& ctx) { ctx.halted = true; }

void HLdi(VMContext& ctx) {
    uint8_t rd = Rf(ctx);
    uint32_t imm = FetchImm32(ctx);
    ctx.reg[rd] = imm;
}

void HMov(VMContext& ctx) {
    uint8_t rd = Rf(ctx), rs = Rf(ctx);
    ctx.reg[rd] = ctx.reg[rs];
}

void HLdb(VMContext& ctx) {
    uint8_t rd = Rf(ctx), rbase = Rf(ctx), roff = Rf(ctx);
    uint32_t addr = ctx.reg[rbase] + ctx.reg[roff];
    ctx.reg[rd] = (addr < ctx.data.size()) ? ctx.data[addr] : 0;
}

void HStb(VMContext& ctx) {
    uint8_t rbase = Rf(ctx), roff = Rf(ctx), rs = Rf(ctx);
    uint32_t addr = ctx.reg[rbase] + ctx.reg[roff];
    if (addr < ctx.data.size())
        ctx.data[addr] = static_cast<uint8_t>(ctx.reg[rs] & 0xFF);
}

void HXor(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), rb = Rf(ctx);
    ctx.reg[rd] = ctx.reg[ra] ^ ctx.reg[rb];
}

void HAnd(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), rb = Rf(ctx);
    ctx.reg[rd] = ctx.reg[ra] & ctx.reg[rb];
}

void HOr(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), rb = Rf(ctx);
    ctx.reg[rd] = ctx.reg[ra] | ctx.reg[rb];
}

void HAdd(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), rb = Rf(ctx);
    ctx.reg[rd] = ctx.reg[ra] + ctx.reg[rb];
}

void HSub(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), rb = Rf(ctx);
    ctx.reg[rd] = ctx.reg[ra] - ctx.reg[rb];
}

void HNot(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx);
    ctx.reg[rd] = ~ctx.reg[ra];
}

void HShl(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), sh = FetchByte(ctx);
    ctx.reg[rd] = ctx.reg[ra] << (sh & 31);
}

void HShr(VMContext& ctx) {
    uint8_t rd = Rf(ctx), ra = Rf(ctx), sh = FetchByte(ctx);
    ctx.reg[rd] = ctx.reg[ra] >> (sh & 31);
}

void HPush(VMContext& ctx) {
    uint8_t rs = Rf(ctx);
    if (ctx.stack.size() < 4096) ctx.stack.push_back(ctx.reg[rs]);
}

void HPop(VMContext& ctx) {
    uint8_t rd = Rf(ctx);
    if (!ctx.stack.empty()) {
        ctx.reg[rd] = ctx.stack.back();
        ctx.stack.pop_back();
    }
}

void HJmp(VMContext& ctx) {
    uint32_t tgt = FetchImm32(ctx);
    ctx.vip = tgt;
}

void HJz(VMContext& ctx) {
    uint8_t rc = Rf(ctx);
    uint32_t tgt = FetchImm32(ctx);
    if (ctx.reg[rc] == 0) ctx.vip = tgt;
}

void HJnz(VMContext& ctx) {
    uint8_t rc = Rf(ctx);
    uint32_t tgt = FetchImm32(ctx);
    if (ctx.reg[rc] != 0) ctx.vip = tgt;
}

void HDecJnz(VMContext& ctx) {
    uint8_t rc = Rf(ctx);
    uint32_t tgt = FetchImm32(ctx);
    ctx.reg[rc] -= 1;
    if (ctx.reg[rc] != 0) ctx.vip = tgt;
}

}  // namespace

const std::array<Handler, kOpCount>& Handlers() {
    static const std::array<Handler, kOpCount> table = [] {
        std::array<Handler, kOpCount> t{};
        t[static_cast<int>(Op::HALT)] = HHalt;
        t[static_cast<int>(Op::LDI)] = HLdi;
        t[static_cast<int>(Op::MOV)] = HMov;
        t[static_cast<int>(Op::LDB)] = HLdb;
        t[static_cast<int>(Op::STB)] = HStb;
        t[static_cast<int>(Op::XOR)] = HXor;
        t[static_cast<int>(Op::AND)] = HAnd;
        t[static_cast<int>(Op::OR)] = HOr;
        t[static_cast<int>(Op::ADD)] = HAdd;
        t[static_cast<int>(Op::SUB)] = HSub;
        t[static_cast<int>(Op::NOT)] = HNot;
        t[static_cast<int>(Op::SHL)] = HShl;
        t[static_cast<int>(Op::SHR)] = HShr;
        t[static_cast<int>(Op::PUSH)] = HPush;
        t[static_cast<int>(Op::POP)] = HPop;
        t[static_cast<int>(Op::JMP)] = HJmp;
        t[static_cast<int>(Op::JZ)] = HJz;
        t[static_cast<int>(Op::JNZ)] = HJnz;
        t[static_cast<int>(Op::DECJNZ)] = HDecJnz;
        return t;
    }();
    return table;
}

}  // namespace vm
