// wb_encrypt — encrypt a 16-byte block through a sealed white-box VM blob.
//
//   wb_encrypt --in FILE [--pass <phrase>] --pt <32 hex>
//
// Unseals the trusted-storage blob and runs the block through the obfuscated
// VM. The key is never reconstructed; encryption happens entirely as encoded
// table lookups inside the VM.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "storage/trusted_storage.h"
#include "vm/vm.h"

static bool ParseHex16(const std::string& s, std::array<uint8_t, 16>& out) {
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
    std::string in_path, pass, pt_hex;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() { return (i + 1 < argc) ? std::string(argv[++i]) : std::string(); };
        if (a == "--in") in_path = next();
        else if (a == "--pass") pass = next();
        else if (a == "--pt") pt_hex = next();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }
    std::array<uint8_t, 16> pt{};
    if (in_path.empty() || !ParseHex16(pt_hex, pt)) {
        std::fprintf(stderr, "usage: wb_encrypt --in FILE [--pass P] --pt <32 hex>\n");
        return 2;
    }

    std::ifstream f(in_path, std::ios::binary);
    if (!f) { std::fprintf(stderr, "cannot read %s\n", in_path.c_str()); return 1; }
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());

    vm::Program prog;
    if (!storage::Unseal(blob, pass, prog)) {
        std::fprintf(stderr, "malformed blob\n");
        return 1;
    }
    auto ct = vm::Run(prog, pt);
    for (uint8_t b : ct) std::printf("%02x", b);
    std::printf("\n");
    return 0;
}
