// Milestone E: end-to-end trusted-storage checks.
//  1. seal -> unseal -> VM run reproduces AES on the FIPS vector;
//  2. key absence: neither the key nor any round key appears as bytes in the
//     sealed blob or the (unsealed) table bank — it is diffused, never stored;
//  3. anti-tamper: flipping a VM code byte, or a wrong passphrase, corrupts the
//     output instead of leaking the correct ciphertext.
#include "test_util.h"
#include "storage/trusted_storage.h"
#include "vm/assembler.h"
#include "vm/vm.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"

using namespace wbaes;

static bool Contains(const std::vector<uint8_t>& hay, const uint8_t* needle, size_t n) {
    if (hay.size() < n) return false;
    for (size_t i = 0; i + n <= hay.size(); ++i)
        if (std::memcmp(hay.data() + i, needle, n) == 0) return true;
    return false;
}

int main() {
    Key128 key = test::FromHex<16>("000102030405060708090a0b0c0d0e0f");
    Block pt = test::FromHex<16>("00112233445566778899aabbccddeeff");
    Block ref = AesEncryptBlock(pt, key);
    const std::string pass = "correct horse battery staple";

    auto wb = GenerateWhiteBox(key, 12345, WBLevel::Internal);
    vm::Program prog = vm::AssembleWhiteBox(*wb, 999, vm::ObfOptions::All());
    std::vector<uint8_t> blob = storage::Seal(prog, pass);

    // (1) seal -> unseal -> run == AES.
    vm::Program un;
    CHECK(storage::Unseal(blob, pass, un));
    auto ct = vm::Run(un, pt);
    Block ctb; for (int i = 0; i < 16; ++i) ctb[i] = ct[i];
    CHECK_EQ_HEX(ctb.data(), 16, test::ToHex(ref.data(), 16).c_str());

    // (2) key-absence: key and all 11 round keys must be absent from the sealed
    // blob AND from the decrypted table bank.
    auto rk = KeyExpansion(key);
    CHECK(!Contains(blob, key.data(), 16));
    CHECK(!Contains(un.data, key.data(), 16));
    for (int r = 0; r <= 10; ++r) {
        CHECK(!Contains(blob, &rk[16 * r], 16));
        CHECK(!Contains(un.data, &rk[16 * r], 16));
    }

    // (3a) tamper: flip one byte in the VM code region -> wrong ciphertext.
    {
        std::vector<uint8_t> t = blob;
        size_t header = 4 + 4 + 4 + 4 + 4 + 8 + 256 + 256;  // up to start of code
        t[header + 7] ^= 0x01;
        vm::Program tp;
        CHECK(storage::Unseal(t, pass, tp));
        // Isolate the binding: the changed logic tag must re-key the data
        // decryption, so the tables differ from the untampered ones. This holds
        // even independent of the executed-bytecode change.
        CHECK(tp.data != un.data);
        auto tct = vm::Run(tp, pt);
        Block tb; for (int i = 0; i < 16; ++i) tb[i] = tct[i];
        CHECK(tb != ref);  // integrity binding corrupts the tables
    }

    // (3b) wrong passphrase -> wrong ciphertext (no correct-key leak).
    {
        vm::Program wp;
        CHECK(storage::Unseal(blob, "wrong passphrase", wp));
        auto wct = vm::Run(wp, pt);
        Block wb2; for (int i = 0; i < 16; ++i) wb2[i] = wct[i];
        CHECK(wb2 != ref);
    }

    return test::Report("test_e2e");
}
