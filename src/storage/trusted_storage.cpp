#include "storage/trusted_storage.h"

#include <cstring>

#include "wbaes/encodings.h"  // wbaes::Rng

namespace storage {

namespace {

constexpr uint8_t kMagic[4] = {'W', 'B', 'T', 'S'};
constexpr uint32_t kVersion = 1;
constexpr uint64_t kKdfDomain = 0x574254535F4B4459ULL;  // "WBTS_KDY"

// FNV-1a 64-bit — a compact non-cryptographic digest, sufficient for binding.
uint64_t Hash64(const uint8_t* p, size_t n, uint64_t seed = 1469598103934665603ULL) {
    uint64_t h = seed;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t KdfStorageKey(const std::string& pass) {
    uint64_t h = Hash64(reinterpret_cast<const uint8_t*>(pass.data()), pass.size());
    return h ^ kKdfDomain;
}

// ---- little-endian append/read helpers ------------------------------------
void PutU32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
}
void PutU64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xFF);
}
bool GetU32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out) {
    if (off + 4 > v.size()) return false;
    out = v[off] | (v[off + 1] << 8) | (v[off + 2] << 16) |
          (static_cast<uint32_t>(v[off + 3]) << 24);
    off += 4;
    return true;
}
bool GetU64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out) {
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= static_cast<uint64_t>(v[off + i]) << (8 * i);
    off += 8;
    return true;
}

// Integrity tag over everything that defines the program *logic* (not the data
// tables). Any tamper here changes the tag and thus the data-decrypt key.
uint64_t LogicTag(uint32_t block_off, uint64_t fw_root,
                  const std::array<uint8_t, 256>& phys_to_op,
                  const std::array<uint8_t, 256>& op_to_phys,
                  const std::vector<uint8_t>& code) {
    uint64_t h = Hash64(reinterpret_cast<const uint8_t*>(&block_off), 4);
    h = Hash64(reinterpret_cast<const uint8_t*>(&fw_root), 8, h);
    h = Hash64(phys_to_op.data(), 256, h);
    h = Hash64(op_to_phys.data(), 256, h);
    h = Hash64(code.data(), code.size(), h);
    return h;
}

// XOR a buffer in place with a keystream derived from `seed`.
void StreamXor(std::vector<uint8_t>& buf, uint64_t seed) {
    wbaes::Rng rng(seed);
    for (auto& b : buf) b ^= static_cast<uint8_t>(rng.next() & 0xFF);
}

}  // namespace

std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase) {
    std::vector<uint8_t> blob;
    blob.insert(blob.end(), kMagic, kMagic + 4);
    PutU32(blob, kVersion);
    PutU32(blob, prog.block_off);
    PutU32(blob, static_cast<uint32_t>(prog.code.size()));
    PutU32(blob, static_cast<uint32_t>(prog.data.size()));
    PutU64(blob, prog.fw_root);
    blob.insert(blob.end(), prog.phys_to_op.begin(), prog.phys_to_op.end());
    blob.insert(blob.end(), prog.op_to_phys.begin(), prog.op_to_phys.end());
    blob.insert(blob.end(), prog.code.begin(), prog.code.end());

    // Seal the table bank under storageKey XOR logicTag (integrity binding).
    uint64_t tag = LogicTag(prog.block_off, prog.fw_root, prog.phys_to_op,
                            prog.op_to_phys, prog.code);
    uint64_t data_seed = KdfStorageKey(passphrase) ^ tag;
    std::vector<uint8_t> sealed = prog.data;
    StreamXor(sealed, data_seed);
    blob.insert(blob.end(), sealed.begin(), sealed.end());
    return blob;
}

bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out) {
    size_t off = 0;
    if (blob.size() < 4 || std::memcmp(blob.data(), kMagic, 4) != 0) return false;
    off = 4;
    uint32_t version, block_off, code_len, data_len;
    uint64_t fw_root;
    if (!GetU32(blob, off, version) || version != kVersion) return false;
    if (!GetU32(blob, off, block_off)) return false;
    if (!GetU32(blob, off, code_len)) return false;
    if (!GetU32(blob, off, data_len)) return false;
    if (!GetU64(blob, off, fw_root)) return false;
    if (off + 512 > blob.size()) return false;

    out = vm::Program();
    out.block_off = block_off;
    out.fw_root = fw_root;
    std::copy(blob.begin() + off, blob.begin() + off + 256, out.phys_to_op.begin());
    off += 256;
    std::copy(blob.begin() + off, blob.begin() + off + 256, out.op_to_phys.begin());
    off += 256;
    if (off + code_len + data_len > blob.size()) return false;

    out.code.assign(blob.begin() + off, blob.begin() + off + code_len);
    off += code_len;
    std::vector<uint8_t> sealed(blob.begin() + off, blob.begin() + off + data_len);

    // Recompute the tag from the (possibly tampered) logic and decrypt the data.
    uint64_t tag = LogicTag(block_off, fw_root, out.phys_to_op,
                            out.op_to_phys, out.code);
    uint64_t data_seed = KdfStorageKey(passphrase) ^ tag;
    StreamXor(sealed, data_seed);
    out.data = std::move(sealed);
    return true;
}

}  // namespace storage
