#include "vm/assembler.h"

#include <array>
#include <cstring>

#include "fw/fwcrypt.h"
#include "obf/blinding.h"
#include "wbaes/aes_tables.h"
#include "wbaes/encodings.h"

namespace vm {

namespace {

// ---- DATA memory layout (the table bank + I/O scratch). --------------------
constexpr uint32_t kTboxOff = 0;
constexpr uint32_t kTboxSize = 10u * 16 * 256;             // 40960
constexpr uint32_t kTyOff = kTboxOff + kTboxSize;
constexpr uint32_t kTySize = 9u * 16 * 256 * 4;            // 147456
constexpr uint32_t kXrOff = kTyOff + kTySize;
constexpr uint32_t kXrSize = 9u * 4 * 4 * 3 * 2 * 256;     // 221184
constexpr uint32_t kStateOff = kXrOff + kXrSize;           // live 16-byte block
constexpr uint32_t kTmpOff = kStateOff + 16;               // T-box outputs
constexpr uint32_t kOutOff = kTmpOff + 16;                 // round output
constexpr uint32_t kDataSize = kOutOff + 16;

uint32_t TboxRow(int m, int i) { return kTboxOff + (uint32_t)(m * 16 + i) * 256; }
uint32_t TyBase(int m, int p) { return kTyOff + (uint32_t)(m * 16 + p) * 256 * 4; }
uint32_t XrRow(int m, int c, int j, int step, int half) {
    return kXrOff + (uint32_t)((((m * 4 + c) * 4 + j) * 3 + step) * 2 + half) * 256;
}

// Fixed register assignment for the (straight-line) compiled program.
enum Reg : uint8_t {
    RZERO = 0, RBASE = 1, RIDX = 2, RVAL = 3,
    RO0 = 4, RO1 = 5, RO2 = 6, RO3 = 7,
    RS = 8, RT0 = 9, RT1 = 10, RT2 = 11, RMASK = 12,
    RM0 = 13, RM1 = 14,  // MBA scratch
    ROP = 15,            // opaque-predicate / junk scratch
};

class Assembler {
public:
    Assembler(uint64_t seed, ObfOptions obf) : rng_(seed), obf_(obf) {
        int minv = obf_.handler_duplication ? 3 : 1;
        int maxv = obf_.handler_duplication ? 5 : 1;
        blinding_ = obf::BuildOpcodeBlinding(rng_, kOpCount, minv, maxv);
    }

    // ---- low-level emit ----------------------------------------------------
    // Pick a random physical byte among this opcode's variants (handler
    // duplication) so the same operation is spelled many ways in the bytecode.
    // Every instruction begins with exactly one op(), so this is also where we
    // record instruction-span boundaries for the firmware encryptor.
    void op(Op o) {
        if (instr_open_)
            spans_.push_back({instr_start_, static_cast<uint32_t>(plain_.size()) - instr_start_});
        instr_start_ = static_cast<uint32_t>(plain_.size());
        instr_open_ = true;
        const auto& v = blinding_.variants[static_cast<int>(o)];
        uint8_t phys = v.size() > 1 ? v[rng_.next() % v.size()] : v.front();
        plain_.push_back(phys);
    }
    void b(uint8_t x) { plain_.push_back(x); }
    void i32(uint32_t v) {
        b(v & 0xFF); b((v >> 8) & 0xFF); b((v >> 16) & 0xFF); b((v >> 24) & 0xFF);
    }

    void LDI(uint8_t rd, uint32_t imm) { op(Op::LDI); b(rd); i32(imm); }
    void LDB(uint8_t rd, uint8_t rbase, uint8_t roff) { op(Op::LDB); b(rd); b(rbase); b(roff); }
    void STB(uint8_t rbase, uint8_t roff, uint8_t rs) { op(Op::STB); b(rbase); b(roff); b(rs); }
    void XOR(uint8_t rd, uint8_t ra, uint8_t rb) { op(Op::XOR); b(rd); b(ra); b(rb); }
    void AND(uint8_t rd, uint8_t ra, uint8_t rb) { op(Op::AND); b(rd); b(ra); b(rb); }
    void OR(uint8_t rd, uint8_t ra, uint8_t rb) { op(Op::OR); b(rd); b(ra); b(rb); }
    void ADD(uint8_t rd, uint8_t ra, uint8_t rb) { op(Op::ADD); b(rd); b(ra); b(rb); }
    void SUB(uint8_t rd, uint8_t ra, uint8_t rb) { op(Op::SUB); b(rd); b(ra); b(rb); }
    void NOT(uint8_t rd, uint8_t ra) { op(Op::NOT); b(rd); b(ra); }
    void SHL(uint8_t rd, uint8_t ra, uint8_t sh) { op(Op::SHL); b(rd); b(ra); b(sh); }
    void SHR(uint8_t rd, uint8_t ra, uint8_t sh) { op(Op::SHR); b(rd); b(ra); b(sh); }
    void JNZ(uint8_t rc, uint32_t tgt) { op(Op::JNZ); b(rc); i32(tgt); }
    void HALT() { op(Op::HALT); }

    // JNZ with a placeholder target; returns the offset of the imm32 to patch.
    size_t EmitJnzPlaceholder(uint8_t rc) {
        op(Op::JNZ); b(rc);
        size_t pos = plain_.size();
        i32(0);
        return pos;
    }
    void Patch(size_t pos, uint32_t v) {
        plain_[pos + 0] = v & 0xFF; plain_[pos + 1] = (v >> 8) & 0xFF;
        plain_[pos + 2] = (v >> 16) & 0xFF; plain_[pos + 3] = (v >> 24) & 0xFF;
    }

    // ---- MBA-obfuscated arithmetic (obf/mba.h). Expansions use only raw ops
    // and RM0/RM1 scratch, so no recursion and rd may alias an input. ---------
    void EmitOr(uint8_t rd, uint8_t ra, uint8_t rb) {
        if (!obf_.mba || (rng_.next() & 1)) { OR(rd, ra, rb); return; }
        XOR(RM0, ra, rb); AND(RM1, ra, rb); ADD(rd, RM0, RM1);  // (x^y)+(x&y)
    }
    void EmitAnd(uint8_t rd, uint8_t ra, uint8_t rb) {
        if (!obf_.mba || (rng_.next() & 1)) { AND(rd, ra, rb); return; }
        OR(RM0, ra, rb); XOR(RM1, ra, rb); SUB(rd, RM0, RM1);   // (x|y)-(x^y)
    }

    // ---- opaque-true guard: JNZ over a junk block, always taken (x|~x != 0).
    // The junk block touches only dead scratch registers, never DATA. ---------
    void EmitOpaqueGuard() {
        if (!obf_.opaque_predicates) return;
        NOT(RM0, ROP);
        OR(RM0, ROP, RM0);                 // RM0 = ROP | ~ROP == 0xFFFFFFFF
        size_t patch = EmitJnzPlaceholder(RM0);
        uint32_t junk_start = static_cast<uint32_t>(plain_.size());
        ADD(ROP, ROP, RM0);                // dead code (skipped at runtime)
        XOR(ROP, ROP, RM1);
        SHL(ROP, ROP, 3);
        uint32_t junk_end = static_cast<uint32_t>(plain_.size());
        junk_ranges_.push_back({junk_start, junk_end});
        Patch(patch, junk_end);            // JNZ jumps over the junk block
    }

    // ---- helpers -----------------------------------------------------------
    void LoadByte(uint8_t rd, uint32_t addr) { LDI(RBASE, addr); LDB(rd, RBASE, RZERO); }
    void StoreByte(uint32_t addr, uint8_t rs) { LDI(RBASE, addr); STB(RBASE, RZERO, rs); }
    void Lookup(uint8_t rd, uint32_t rowBase, uint8_t ridx) {
        LDI(RBASE, rowBase); LDB(rd, RBASE, ridx);
    }

    // rDst = encoded XOR of encoded bytes in rA, rB via type-IV nibble tables.
    // The OR/AND index arithmetic is routed through the MBA emitters.
    void XorNibble(uint8_t rDst, uint8_t rA, uint8_t rB, uint32_t baseHi, uint32_t baseLo) {
        // high plane: idx = (a & 0xF0) | (b >> 4)
        SHR(RT0, rA, 4); SHL(RT0, RT0, 4);
        SHR(RT1, rB, 4);
        EmitOr(RT2, RT0, RT1);
        LDI(RBASE, baseHi); LDB(RT0, RBASE, RT2);   // hi nibble result
        // low plane: idx = ((a & 0xF) << 4) | (b & 0xF)
        EmitAnd(RT1, rA, RMASK); SHL(RT1, RT1, 4);
        EmitAnd(RT2, rB, RMASK);
        EmitOr(RT2, RT1, RT2);
        LDI(RBASE, baseLo); LDB(RT1, RBASE, RT2);   // lo nibble result
        // combine
        SHL(RT0, RT0, 4);
        EmitOr(rDst, RT0, RT1);
    }

    // Hand the plaintext bytecode (+ instruction spans + junk ranges) to the
    // firmware encryptor. Data image is filled in by the caller.
    fw::AssembledProgram FinishPlain() {
        if (instr_open_)
            spans_.push_back({instr_start_, static_cast<uint32_t>(plain_.size()) - instr_start_});
        instr_open_ = false;
        fw::AssembledProgram out;
        out.plain = std::move(plain_);
        out.spans = std::move(spans_);
        out.junk_ranges = std::move(junk_ranges_);
        out.op_to_phys = blinding_.op_to_phys;
        out.phys_to_op = blinding_.phys_to_op;
        out.block_off = kStateOff;
        return out;
    }

private:
    wbaes::Rng rng_;
    ObfOptions obf_;
    obf::OpcodeBlinding blinding_;
    std::vector<uint8_t> plain_;
    std::vector<std::pair<uint32_t, uint32_t>> spans_;
    std::vector<std::pair<uint32_t, uint32_t>> junk_ranges_;
    uint32_t instr_start_ = 0;
    bool instr_open_ = false;
};

}  // namespace

Program AssembleWhiteBox(const wbaes::WhiteBox& wb, uint64_t seed, ObfOptions obf) {
    using wbaes::ShiftRowsSrc;
    Assembler a(seed, obf);

    // Program preamble: constants (ROP seeds the opaque predicates).
    a.LDI(RZERO, 0);
    a.LDI(RMASK, 0x0F);
    a.LDI(ROP, 0x9E3779B9u);

    // Rounds 0..8: T-box -> ShiftRows -> Tyi -> XOR tree.
    for (int m = 0; m < 9; ++m) {
        a.EmitOpaqueGuard();  // bogus control flow between rounds
        // t[i] = tbox[m][i][state[i]]  -> TMP[i]
        for (int i = 0; i < 16; ++i) {
            a.LoadByte(RIDX, kStateOff + i);
            a.Lookup(RVAL, TboxRow(m, i), RIDX);
            a.StoreByte(kTmpOff + i, RVAL);
        }
        // per column / lane: gather 4 Tyi operands and fold them.
        for (int c = 0; c < 4; ++c) {
            for (int j = 0; j < 4; ++j) {
                const uint8_t opnd[4] = {RO0, RO1, RO2, RO3};
                for (int mm = 0; mm < 4; ++mm) {
                    int p = 4 * c + mm;
                    int src = ShiftRowsSrc(p);
                    a.LoadByte(RIDX, kTmpOff + src);       // tval
                    a.SHL(RIDX, RIDX, 2);                  // tval * 4
                    a.Lookup(opnd[mm], TyBase(m, p) + j, RIDX);
                }
                a.XorNibble(RS, RO0, RO1, XrRow(m, c, j, 0, 0), XrRow(m, c, j, 0, 1));
                a.XorNibble(RS, RS, RO2, XrRow(m, c, j, 1, 0), XrRow(m, c, j, 1, 1));
                a.XorNibble(RS, RS, RO3, XrRow(m, c, j, 2, 0), XrRow(m, c, j, 2, 1));
                a.StoreByte(kOutOff + 4 * c + j, RS);
            }
        }
        // state = out
        for (int i = 0; i < 16; ++i) {
            a.LoadByte(RVAL, kOutOff + i);
            a.StoreByte(kStateOff + i, RVAL);
        }
    }

    // Final round (index 9): T-box (k9,k10 folded), then ShiftRows into STATE.
    for (int i = 0; i < 16; ++i) {
        a.LoadByte(RIDX, kStateOff + i);
        a.Lookup(RVAL, TboxRow(9, i), RIDX);
        a.StoreByte(kTmpOff + i, RVAL);
    }
    for (int dst = 0; dst < 16; ++dst) {
        a.LoadByte(RVAL, kTmpOff + ShiftRowsSrc(dst));
        a.StoreByte(kStateOff + dst, RVAL);
    }
    a.HALT();

    fw::AssembledProgram prog = a.FinishPlain();

    // Serialize the table bank into the initial DATA image.
    prog.data.assign(kDataSize, 0);
    for (int m = 0; m < 10; ++m)
        for (int i = 0; i < 16; ++i)
            std::memcpy(&prog.data[TboxRow(m, i)], wb.tbox[m][i].data(), 256);
    for (int m = 0; m < 9; ++m)
        for (int p = 0; p < 16; ++p)
            for (int v = 0; v < 256; ++v)
                std::memcpy(&prog.data[TyBase(m, p) + v * 4], wb.ty[m][p][v].data(), 4);
    for (int m = 0; m < 9; ++m)
        for (int c = 0; c < 4; ++c)
            for (int j = 0; j < 4; ++j)
                for (int step = 0; step < 3; ++step)
                    for (int half = 0; half < 2; ++half)
                        std::memcpy(&prog.data[XrRow(m, c, j, step, half)],
                                    wb.xr[m][c][j][step][half].data(), 256);

    // Encrypt the firmware (separate toolchain): context-keyed, feedback-evolving
    // decode bound to the interpreter fingerprint.
    return fw::EncryptFirmware(prog, seed);
}

}  // namespace vm
