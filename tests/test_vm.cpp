// Milestone C: the VM executing the compiled white-box must match both the
// C++ white-box interpreter and the reference AES oracle. Any mismatch here is
// a VM bug, since the same verified table blob feeds both paths.
#include "test_util.h"
#include "vm/assembler.h"
#include "vm/vm.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"
#include "wbaes/wb_interp.h"

using namespace wbaes;

static void RunLevel(WBLevel level, const char* name, uint64_t wb_seed,
                     uint64_t vm_seed, const Key128& key, bool check_fips,
                     vm::ObfOptions obf = vm::ObfOptions::All()) {
    auto wb = GenerateWhiteBox(key, wb_seed, level);
    vm::Program prog = vm::AssembleWhiteBox(*wb, vm_seed, obf);

    if (check_fips) {
        // FIPS-197 vector through the full VM.
        Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
        auto out = vm::Run(prog, pt);
        Block vm_ct;
        for (int i = 0; i < 16; ++i) vm_ct[i] = out[i];
        CHECK_EQ_HEX(vm_ct.data(), 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }

    // Differential vs interpreter and oracle over random blocks.
    uint32_t st = 0xC0FFEEu ^ static_cast<uint32_t>(vm_seed);
    for (int trial = 0; trial < 64; ++trial) {
        Block p{};
        for (auto& x : p) { st = st * 1664525u + 1013904223u; x = static_cast<uint8_t>(st >> 24); }
        auto vres = vm::Run(prog, p);
        Block vblk; for (int i = 0; i < 16; ++i) vblk[i] = vres[i];
        Block iblk = WhiteBoxEncrypt(*wb, p);
        Block ablk = AesEncryptBlock(p, key);
        if (vblk != iblk || vblk != ablk) {
            std::printf("  FAIL [%s] trial %d: vm=%s interp=%s aes=%s\n", name, trial,
                        test::ToHex(vblk.data(), 16).c_str(),
                        test::ToHex(iblk.data(), 16).c_str(),
                        test::ToHex(ablk.data(), 16).c_str());
            ++test::failures();
            break;
        }
    }
    std::printf("  [%s] VM matches interp+AES (wb_seed=%llu vm_seed=%llu, code=%zu B)\n",
                name, (unsigned long long)wb_seed, (unsigned long long)vm_seed,
                prog.code.size());
}

// vm::Run must carry NO state between blocks.
//
// This guards the per-block DATA copy, which is easy to mistake for dead weight
// (only 48 of ~400 KB are ever written) but is also the reset that defeats
// differential fault analysis: a fault injected into the table bank must not
// survive into the next block. Any change that hoists the copy out of the
// per-block path — a persistent arena, a shared table view — breaks that, and
// this test is what should fail when it does. See the note on Run in vm/vm.h.
static void TestStatelessness() {
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    auto wb = GenerateWhiteBox(key, 42, WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, 7, vm::ObfOptions::All());
    Block fips_pt = test::FromHex<16>("00112233445566778899aabbccddeeff");

    // Interleave other blocks around the reference vector: if any scratch (TMP,
    // OUT, STATE) or table byte leaked across calls, the repeat would drift.
    for (int i = 0; i < 4; ++i) {
        Block noise = fips_pt;
        noise[0] = static_cast<uint8_t>(0xA0 + i);
        (void)vm::Run(prog, noise);

        auto out = vm::Run(prog, fips_pt);
        CHECK_EQ_HEX(out.data(), 16, "69c4e0d86a7b0430d8cdb78070b4c55a");
    }
    std::printf("  [state] Run is stateless across interleaved blocks\n");
}

int main() {
    Key128 fips = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    // No obfuscation (bare bytecode) and full obfuscation must both be correct.
    RunLevel(WBLevel::Naked, "naked/plain", 1, 100, fips, true, vm::ObfOptions::None());
    RunLevel(WBLevel::Internal, "internal/plain", 42, 7, fips, true, vm::ObfOptions::None());
    RunLevel(WBLevel::Internal, "internal/hardened", 42, 7, fips, true, vm::ObfOptions::All());
    RunLevel(WBLevel::Internal, "internal/hardened", 0xABCDEF, 0x999, fips, true);

    // Random-key dimension through the full VM.
    uint32_t kst = 0x0BADF00Du;
    for (int t = 0; t < 4; ++t) {
        Key128 rk{};
        for (auto& b : rk) { kst = kst * 1664525u + 1013904223u; b = static_cast<uint8_t>(kst >> 24); }
        RunLevel(WBLevel::Internal, "internal-randkey", 300 + t, 400 + t, rk, false);
    }

    TestStatelessness();
    return test::Report("test_vm");
}
