// wb_keygen — compile an AES-128 key into a sealed trusted-storage blob.
//
//   wb_keygen --key <32 hex> [--pass <phrase>] [--seed N] [--plain]
//             [--kdf light|medium|heavy] --out FILE
//
// The key is consumed here and never written out: the blob contains only the
// white-box table network (key diffused) inside the obfuscated VM.
//
// --kdf picks what every later wbc_open of this blob pays. It defaults to
// `heavy` deliberately: forgetting the flag must not silently produce a blob
// with no passphrase-guessing resistance. See storage::KdfTier for when each
// tier is sound — `light` requires a high-entropy machine-generated passphrase.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "storage/trusted_storage.h"
#include "vm/assembler.h"
#include "wbaes/aes_ref.h"
#include "wbaes/wb_generator.h"

static bool ParseHex16(const std::string& s, wbaes::Key128& out) {
    if (s.size() != 32) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < 16; ++i) {
        int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// --kdf name -> tier. Returns false for anything unrecognised, so a typo is a
// usage error rather than a silent fall back to some default cost.
static bool ParseTier(const std::string& s, storage::KdfTier& out) {
    if (s == "light")  { out = storage::KdfTier::kNone; return true; }
    if (s == "medium") { out = storage::KdfTier::kLow;  return true; }
    if (s == "heavy")  { out = storage::KdfTier::kHigh; return true; }
    return false;
}

int main(int argc, char** argv) {
    std::string key_hex, pass, out_path, kdf_name = "heavy";
    uint64_t seed = 0xA5F00D;
    bool plain = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? std::string(argv[++i]) : std::string(); };
        if (a == "--key") key_hex = next();
        else if (a == "--pass") pass = next();
        else if (a == "--seed") seed = std::strtoull(next().c_str(), nullptr, 0);
        else if (a == "--plain") plain = true;
        else if (a == "--kdf") kdf_name = next();
        else if (a == "--out") out_path = next();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }
    storage::KdfTier tier = storage::KdfTier::kHigh;
    if (!ParseTier(kdf_name, tier)) {
        std::fprintf(stderr, "--kdf must be light, medium or heavy (got '%s')\n",
                     kdf_name.c_str());
        return 2;
    }
    wbaes::Key128 key{};
    if (!ParseHex16(key_hex, key) || out_path.empty()) {
        std::fprintf(stderr,
                     "usage: wb_keygen --key <32 hex> [--pass P] [--seed N] "
                     "[--plain] [--kdf light|medium|heavy] --out FILE\n");
        return 2;
    }

    auto wb = wbaes::GenerateWhiteBox(key, seed, wbaes::WBLevel::Internal);

    // Sealed VM blob (for the SDK / CLI runtime path).
    if (!out_path.empty()) {
        vm::ObfOptions obf = plain ? vm::ObfOptions::None() : vm::ObfOptions::All();
        vm::Program prog = vm::AssembleWhiteBox(*wb, seed ^ 0x9999, obf);
        std::vector<uint8_t> blob = storage::Seal(prog, pass, tier);
        std::ofstream f(out_path, std::ios::binary);
        if (!f) { std::fprintf(stderr, "cannot write %s\n", out_path.c_str()); return 1; }
        f.write(reinterpret_cast<const char*>(blob.data()),
                static_cast<std::streamsize>(blob.size()));
        /* Report the tier: it is invisible in the output bytes but decides every
         * later wbc_open's cost AND the blob's guessing resistance, so it should
         * not be something you have to remember you chose. */
        std::printf("sealed white-box -> %s (%zu bytes, %s bytecode, %zu B code, "
                    "kdf=%s)\n",
                    out_path.c_str(), blob.size(), plain ? "plain" : "hardened",
                    prog.code.size(), kdf_name.c_str());
        if (tier == storage::KdfTier::kNone)
            std::fprintf(stderr,
                         "wb_keygen: kdf=light means NO passphrase-guessing "
                         "resistance — only sound if --pass is >= 128 bits of "
                         "machine-generated randomness\n");
    }

    return 0;
}
