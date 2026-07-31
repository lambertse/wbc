// Milestone E: end-to-end trusted-storage checks.
//  1. seal -> unseal -> VM run reproduces AES on the FIPS vector;
//  2. key absence: neither the key nor any round key appears as bytes in the
//     sealed blob or the (unsealed) table bank — it is diffused, never stored;
//  3. anti-tamper: flipping any blob byte, or a wrong passphrase, fails AEAD
//     authentication so the blob does not unseal (no correct-key leak).
#include <cstring>

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

    // (3a) tamper: flip one byte in the VM code region (which is AEAD
    // associated data) -> authentication fails, Unseal returns false.
    {
        std::vector<uint8_t> t = blob;
        // v2 header up to start of code: magic(4)+version(4)+salt(16)+nonce(24)+
        // block_off(4)+code_len(4)+data_len(4)+fw_root(8)+phys(256)+op(256).
        size_t code_off = 4 + 4 + 16 + 24 + 4 + 4 + 4 + 8 + 256 + 256;
        t[code_off + 7] ^= 0x01;
        vm::Program tp;
        CHECK(!storage::Unseal(t, pass, tp));
    }

    // (3b) tamper in the ciphertext (encrypted table bank) -> auth fails.
    {
        std::vector<uint8_t> t = blob;
        t[t.size() - 1] ^= 0x01;
        vm::Program tp;
        CHECK(!storage::Unseal(t, pass, tp));
    }

    // (3c) wrong passphrase -> derives a different key, auth fails.
    {
        vm::Program wp;
        CHECK(!storage::Unseal(blob, "wrong passphrase", wp));
    }

    // (3d) same program + passphrase sealed twice -> different bytes (random
    // salt/nonce), but both unseal to the identical table bank.
    {
        std::vector<uint8_t> blob2 = storage::Seal(prog, pass);
        CHECK(blob2.size() == blob.size());
        CHECK(blob2 != blob);
        vm::Program un2;
        CHECK(storage::Unseal(blob2, pass, un2));
        CHECK(un2.data == un.data);
    }

    return test::Report("test_e2e");
}
