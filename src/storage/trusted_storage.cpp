#include "storage/trusted_storage.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <new>
#include <stdexcept>

namespace storage {

namespace {

constexpr uint8_t kMagic[4] = {'W', 'B', 'T', 'S'};
// v3: added the LDBI/STBI immediate-base opcodes and widened the register file to
// 32. Both change how a code stream decodes (kOpCount feeds the interpreter
// fingerprint, hence the decode root), so a v2 blob cannot be executed by a v3
// runtime. Rejected on the version check below rather than mis-decoded.
constexpr uint32_t kVersion = 3;

// KDF cost. INTERACTIVE-class is the mobile-appropriate tier (a few MB..tens of
// MB, sub-second on a phone); do NOT use the _SENSITIVE tier here (256MB+ /
// multi-second would make wbc_open unusable on-device). Each passphrase guess
// costs one Argon2id evaluation, which is what defuses offline guessing.
constexpr unsigned long long kOpsLimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
constexpr size_t kMemLimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

constexpr size_t kSaltBytes = crypto_pwhash_SALTBYTES;                        // 16
constexpr size_t kNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
constexpr size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;     // 32
constexpr size_t kTagBytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;       // 16

void EnsureSodium() {
    // sodium_init() is idempotent and returns 1 if already initialized.
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

// Derive the 32-byte AEAD key from the passphrase and salt via Argon2id.
// Returns false if the KDF fails (e.g. memory allocation).
bool DeriveKey(const std::string& pass, const uint8_t salt[kSaltBytes],
               uint8_t out_key[kKeyBytes]) {
    return crypto_pwhash(out_key, kKeyBytes, pass.data(), pass.size(), salt,
                         kOpsLimit, kMemLimit, crypto_pwhash_ALG_ARGON2ID13) == 0;
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

}  // namespace

// Blob layout (v2):
//   magic[4] | version(u32) | salt[16] | nonce[24] |
//   block_off(u32) | code_len(u32) | data_len(u32) | fw_root(u64) |
//   phys_to_op[256] | op_to_phys[256] | code[code_len] |
//   ciphertext[data_len + 16]
// Everything before `ciphertext` is the AEAD associated data (authenticated but
// not encrypted); `ciphertext` is AEAD(prog.data) — the diffused-key table bank.
std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase) {
    EnsureSodium();

    std::vector<uint8_t> blob;
    blob.insert(blob.end(), kMagic, kMagic + 4);
    PutU32(blob, kVersion);

    const size_t salt_off = blob.size();
    blob.resize(blob.size() + kSaltBytes + kNonceBytes);
    uint8_t* salt = blob.data() + salt_off;
    uint8_t* nonce = salt + kSaltBytes;
    randombytes_buf(salt, kSaltBytes);
    randombytes_buf(nonce, kNonceBytes);

    PutU32(blob, prog.block_off);
    PutU32(blob, static_cast<uint32_t>(prog.code.size()));
    PutU32(blob, static_cast<uint32_t>(prog.data.size()));
    PutU64(blob, prog.fw_root);
    blob.insert(blob.end(), prog.phys_to_op.begin(), prog.phys_to_op.end());
    blob.insert(blob.end(), prog.op_to_phys.begin(), prog.op_to_phys.end());
    blob.insert(blob.end(), prog.code.begin(), prog.code.end());

    // The whole header so far is the associated data. Re-read salt/nonce from
    // the (possibly reallocated) buffer.
    const size_t header_len = blob.size();
    uint8_t key[kKeyBytes];
    if (!DeriveKey(passphrase, blob.data() + salt_off, key)) {
        sodium_memzero(key, sizeof key);
        throw std::bad_alloc();  // Argon2id arena allocation failed
    }

    std::vector<uint8_t> ct(prog.data.size() + kTagBytes);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len,
        prog.data.data(), prog.data.size(),
        blob.data(), header_len,      // associated data = header
        nullptr,
        blob.data() + salt_off + kSaltBytes,  // nonce
        key);
    sodium_memzero(key, sizeof key);

    ct.resize(static_cast<size_t>(ct_len));
    blob.insert(blob.end(), ct.begin(), ct.end());
    return blob;
}

bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out) {
    EnsureSodium();

    size_t off = 0;
    if (blob.size() < 4 || std::memcmp(blob.data(), kMagic, 4) != 0) return false;
    off = 4;
    uint32_t version, block_off, code_len, data_len;
    uint64_t fw_root;
    if (!GetU32(blob, off, version) || version != kVersion) return false;
    if (off + kSaltBytes + kNonceBytes > blob.size()) return false;
    const size_t salt_off = off;
    off += kSaltBytes + kNonceBytes;
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
    if (off + code_len > blob.size()) return false;
    out.code.assign(blob.begin() + off, blob.begin() + off + code_len);
    off += code_len;

    // Everything from the start of the blob up to here is the associated data;
    // the remainder is ciphertext+tag and must be exactly data_len + kTagBytes.
    const size_t header_len = off;
    const size_t ct_len = static_cast<size_t>(data_len) + kTagBytes;
    if (header_len + ct_len != blob.size()) return false;

    uint8_t key[kKeyBytes];
    if (!DeriveKey(passphrase, blob.data() + salt_off, key)) {
        sodium_memzero(key, sizeof key);
        return false;
    }

    out.data.resize(data_len);
    unsigned long long pt_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.data.data(), &pt_len, nullptr,
        blob.data() + header_len, ct_len,
        blob.data(), header_len,                 // associated data = header
        blob.data() + salt_off + kSaltBytes,     // nonce
        key);
    sodium_memzero(key, sizeof key);
    if (rc != 0) return false;  // wrong passphrase or tampered blob
    out.data.resize(static_cast<size_t>(pt_len));
    return true;
}

}  // namespace storage
