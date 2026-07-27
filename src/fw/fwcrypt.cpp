#include "fw/fwcrypt.h"

#include "fw/fw_schedule.h"
#include "wbaes/encodings.h"  // wbaes::Rng as the per-instruction keystream

namespace fw {

namespace {
bool InJunk(const std::vector<std::pair<uint32_t, uint32_t>>& ranges, uint32_t off) {
    for (const auto& r : ranges)
        if (off >= r.first && off < r.second) return true;
    return false;
}
}  // namespace

vm::Program EncryptFirmware(const AssembledProgram& a, uint64_t seed) {
    vm::Program prog;
    prog.op_to_phys = a.op_to_phys;
    prog.phys_to_op = a.phys_to_op;
    prog.data = a.data;
    prog.block_off = a.block_off;
    prog.fw_root = DeriveRoot(seed);

    // The root used for decoding also binds the interpreter fingerprint; this is
    // recomputed (never stored) at run time, so tampering the opcode map breaks
    // every decode.
    const uint64_t eff_root = prog.fw_root ^ InterpFingerprint(a.op_to_phys);

    prog.code = a.plain;  // encrypt in place
    uint64_t key_reg = eff_root;

    for (const auto& span : a.spans) {
        uint32_t ip = span.first, len = span.second;
        if (InJunk(a.junk_ranges, ip)) {
            // Never executed: fill with an independent stream, do not advance the
            // execution key (runtime never decodes these bytes).
            wbaes::Rng ks(Splitmix(eff_root ^ (0xBADC0FFEE0DDF00DULL + ip)));
            for (uint32_t p = 0; p < len; ++p)
                prog.code[ip + p] = a.plain[ip + p] ^ static_cast<uint8_t>(ks.next() & 0xFF);
            continue;
        }
        wbaes::Rng ks(PrfSeed(eff_root, key_reg, ip));
        uint32_t fold = FoldInit();
        for (uint32_t p = 0; p < len; ++p) {
            uint8_t b = a.plain[ip + p];
            prog.code[ip + p] = b ^ static_cast<uint8_t>(ks.next() & 0xFF);
            fold = FoldByte(fold, b);
        }
        key_reg = UpdateKeyReg(key_reg, fold, ip);
    }
    return prog;
}

}  // namespace fw
