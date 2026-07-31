// wb_keygen — compile an AES-128 key into a sealed trusted-storage blob.
//
//   wb_keygen --key <32 hex> [--pass <phrase>] [--seed N] [--plain] --out FILE
//
// The key is consumed here and never written out: the blob contains only the
// white-box table network (key diffused) inside the obfuscated VM.
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

int main(int argc, char** argv) {
    std::string key_hex, pass, out_path;
    uint64_t seed = 0xA5F00D;
    bool plain = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? std::string(argv[++i]) : std::string(); };
        if (a == "--key") key_hex = next();
        else if (a == "--pass") pass = next();
        else if (a == "--seed") seed = std::strtoull(next().c_str(), nullptr, 0);
        else if (a == "--plain") plain = true;
        else if (a == "--out") out_path = next();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }
    wbaes::Key128 key{};
    if (!ParseHex16(key_hex, key) || out_path.empty()) {
        std::fprintf(stderr,
                     "usage: wb_keygen --key <32 hex> [--pass P] [--seed N] "
                     "[--plain] --out FILE\n");
        return 2;
    }

    auto wb = wbaes::GenerateWhiteBox(key, seed, wbaes::WBLevel::Internal);

    // Sealed VM blob (for the SDK / CLI runtime path).
    if (!out_path.empty()) {
        vm::ObfOptions obf = plain ? vm::ObfOptions::None() : vm::ObfOptions::All();
        vm::Program prog = vm::AssembleWhiteBox(*wb, seed ^ 0x9999, obf);
        std::vector<uint8_t> blob = storage::Seal(prog, pass);
        std::ofstream f(out_path, std::ios::binary);
        if (!f) { std::fprintf(stderr, "cannot write %s\n", out_path.c_str()); return 1; }
        f.write(reinterpret_cast<const char*>(blob.data()),
                static_cast<std::streamsize>(blob.size()));
        std::printf("sealed white-box -> %s (%zu bytes, %s bytecode, %zu B code)\n",
                    out_path.c_str(), blob.size(), plain ? "plain" : "hardened",
                    prog.code.size());
    }

    return 0;
}
