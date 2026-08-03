// W1: context-keyed firmware decode + anti-tamper.
//  - correctness: context-decode VM == AES (also covered by test_vm);
//  - byte-tamper CASCADE: flipping any code byte corrupts the output;
//  - interpreter binding: changing the opcode map breaks decode (can't re-map);
//  - no stored keystream: decode derives from fw_root only; code looks random.
#include <cmath>
#include <utility>  // std::swap

#include "storage/trusted_storage.h"
#include "test_util.h"
#include "vm/assembler.h"
#include "vm/vm.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"

using namespace wbaes;

static Block RunBlock(const vm::Program& p, const Block& pt) {
    auto o = vm::Run(p, pt);
    Block b; for (int i = 0; i < 16; ++i) b[i] = o[i];
    return b;
}

static double Entropy(const std::vector<uint8_t>& v) {
    long f[256] = {0};
    for (uint8_t b : v) f[b]++;
    double h = 0;
    for (int i = 0; i < 256; ++i)
        if (f[i]) { double p = double(f[i]) / v.size(); h -= p * std::log2(p); }
    return h;
}

// A v2 blob must be REJECTED by a v3 runtime, not mis-executed.
//
// v3 added the LDBI/STBI opcodes, which changed kOpCount, which changes the
// interpreter fingerprint and hence the decode root — so v2 code decodes to
// garbage under v3. The version check in trusted_storage.cpp is what turns that
// into a clean WBC_ERR_FORMAT. This forges a v2 header from a real v3 blob
// (byte 4 is the little-endian version word) and asserts Unseal declines it.
static void TestVersionGate() {
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    auto wb = GenerateWhiteBox(key, 5, WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, 6, vm::ObfOptions::All());
    std::vector<uint8_t> blob = storage::Seal(prog, "pw");

    vm::Program out;
    CHECK(storage::Unseal(blob, "pw", out));  // the real thing still opens

    CHECK(blob.size() > 8);
    CHECK(blob[4] == 3);  // current kVersion, little-endian at offset 4
    std::vector<uint8_t> old = blob;
    old[4] = 2;  // claim to be v2
    vm::Program ignored;
    CHECK(!storage::Unseal(old, "pw", ignored));
    std::printf("  [version] a v2-stamped blob is refused by the v3 runtime\n");
}

int main() {
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
    Block ref = AesEncryptBlock(pt, key);

    auto wb = GenerateWhiteBox(key, 12345, WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, 777, vm::ObfOptions::All());

    // Correctness with context-keyed decode.
    CHECK(RunBlock(prog, pt) == ref);
    // Deterministic (no per-run keystream state leaking across runs).
    CHECK(RunBlock(prog, pt) == RunBlock(prog, pt));
    // Encrypted firmware looks random (no liftable structure).
    double h = Entropy(prog.code);
    std::printf("  code=%zu bytes entropy=%.3f bits/byte\n", prog.code.size(), h);
    CHECK(h > 7.5);

    // Byte-tamper cascade: flipping any single code byte must corrupt output.
    // Test an early, middle, and late byte.
    for (size_t pos : {size_t(5), prog.code.size() / 2, prog.code.size() - 3}) {
        vm::Program t = prog;
        t.code[pos] ^= 0x01;
        Block got = RunBlock(t, pt);
        if (got == ref) {
            std::printf("  FAIL tamper at %zu did not corrupt output\n", pos);
            ++test::failures();
        }
    }

    // Interpreter binding: the decode root hashes the opcode map, so re-mapping
    // an opcode (even consistently) changes the effective root -> decode breaks.
    {
        vm::Program t = prog;
        // swap two physical opcode assignments consistently.
        uint8_t a = t.op_to_phys[static_cast<int>(vm::Op::XOR)];
        uint8_t b = t.op_to_phys[static_cast<int>(vm::Op::ADD)];
        std::swap(t.op_to_phys[static_cast<int>(vm::Op::XOR)],
                  t.op_to_phys[static_cast<int>(vm::Op::ADD)]);
        std::swap(t.phys_to_op[a], t.phys_to_op[b]);
        CHECK(RunBlock(t, pt) != ref);  // fingerprint changed -> wrong output
    }

    // Sanity: two VM seeds diversify the firmware image.
    vm::Program prog2 = vm::AssembleWhiteBox(*wb, 778, vm::ObfOptions::All());
    CHECK(prog.code != prog2.code);
    CHECK(RunBlock(prog2, pt) == ref);

    TestVersionGate();
    return test::Report("test_fw");
}
