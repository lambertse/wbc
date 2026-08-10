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
//
// v4: the KDF tier moved from a compile-time constant into the header, which
// shifts every field after it. A v3 blob's `salt` sits where v4 reads the tier,
// so a v3 blob MUST be rejected rather than reinterpreted — the exact-match
// version check below does that. There is no dual-read path: v3 blobs must be
// re-provisioned.
constexpr uint32_t kVersion = 4;

constexpr size_t kSaltBytes = crypto_pwhash_SALTBYTES;                        // 16
constexpr size_t kNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;  // 24
constexpr size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;     // 32
constexpr size_t kTagBytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;       // 16

// Offset of the tier field: magic[4] | version(u32). PeekTier reads it without
// touching anything else.
constexpr size_t kTierOff = 8;
// Bytes needed before the tier is readable.
constexpr size_t kTierEnd = kTierOff + 4;

// Domain separation for the kNone (HKDF) path. Binds the derived key to this
// format version and purpose, so the same machine secret used elsewhere cannot
// collide with a seal key.
constexpr char kHkdfInfo[] = "WBTS-v4-seal-key";

void EnsureSodium() {
    // sodium_init() is idempotent and returns 1 if already initialized.
    if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
}

// Derive the 32-byte AEAD key from the passphrase and salt, at `tier`'s cost.
// Returns false if the KDF fails (e.g. Argon2id memory allocation).
//
// kNone is HKDF-SHA256: extract(salt, pass) then expand(info). This is the
// correct construction for a high-entropy input — there is nothing for a
// memory-hard function to protect. It is NOT a weakened Argon2id, and the
// entropy precondition is the caller's to meet (see KdfTier in the header).
bool DeriveKey(const std::string& pass, const uint8_t salt[kSaltBytes],
               KdfTier tier, uint8_t out_key[kKeyBytes]) {
    if (tier == KdfTier::kNone) {
        static_assert(kKeyBytes == crypto_kdf_hkdf_sha256_KEYBYTES,
                      "HKDF-SHA256 PRK must be the AEAD key size");
        uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
        // The salt is the HKDF salt and the passphrase the input keying
        // material — i.e. the per-blob salt still diversifies the derived key,
        // exactly as it does on the Argon2id path.
        if (crypto_kdf_hkdf_sha256_extract(prk, salt, kSaltBytes,
                                           reinterpret_cast<const unsigned char*>(pass.data()),
                                           pass.size()) != 0) {
            sodium_memzero(prk, sizeof prk);
            return false;
        }
        const int rc = crypto_kdf_hkdf_sha256_expand(out_key, kKeyBytes, kHkdfInfo,
                                                     sizeof kHkdfInfo - 1, prk);
        sodium_memzero(prk, sizeof prk);
        return rc == 0;
    }
    const KdfParams p = ParamsForTier(tier);
    return crypto_pwhash(out_key, kKeyBytes, pass.data(), pass.size(), salt,
                         p.ops, p.mem, crypto_pwhash_ALG_ARGON2ID13) == 0;
}

// ---- little-endian append/read helpers ------------------------------------
void PutU32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xFF); v.push_back((x >> 8) & 0xFF);
    v.push_back((x >> 16) & 0xFF); v.push_back((x >> 24) & 0xFF);
}
void PutU64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xFF);
}
// Pointer form so Unseal can read straight out of the caller's buffer rather
// than a copy. `off + N` cannot overflow for any reachable off: every caller
// advances off only after a successful bounds check against n.
bool GetU32(const uint8_t* v, size_t n, size_t& off, uint32_t& out) {
    if (off + 4 > n) return false;
    out = v[off] | (v[off + 1] << 8) | (v[off + 2] << 16) |
          (static_cast<uint32_t>(v[off + 3]) << 24);
    off += 4;
    return true;
}
bool GetU64(const uint8_t* v, size_t n, size_t& off, uint64_t& out) {
    if (off + 8 > n) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= static_cast<uint64_t>(v[off + i]) << (8 * i);
    off += 8;
    return true;
}

}  // namespace

// ---- tier metadata ---------------------------------------------------------

KdfParams ParamsForTier(KdfTier tier) {
    switch (tier) {
        // Not Argon2id: kNone derives with HKDF-SHA256. Reported as {0, 0} so a
        // caller cannot accidentally hand these to crypto_pwhash (which would
        // reject them anyway — 0 is below OPSLIMIT_MIN).
        case KdfTier::kNone: return {0, 0};
        // 16 MiB / 2 passes. Keeps INTERACTIVE's pass count and cuts memory 4x:
        // memory is Argon2id's primary hardness parameter, and a 16 MiB arena is
        // far friendlier to allocate during app startup than 64 MiB.
        case KdfTier::kLow: return {2, 16u * 1024 * 1024};
        // libsodium's INTERACTIVE tier: 64 MiB / 2 passes. Do NOT raise this to
        // the _SENSITIVE tier (256MB+/multi-second) — it would make wbc_open
        // unusable on-device.
        case KdfTier::kHigh:
            return {crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE};
    }
    return {0, 0};  // unreachable for a validated tier
}

bool IsValidTier(uint32_t v) {
    return v == static_cast<uint32_t>(KdfTier::kNone) ||
           v == static_cast<uint32_t>(KdfTier::kLow) ||
           v == static_cast<uint32_t>(KdfTier::kHigh);
}

const char* TierName(KdfTier tier) {
    switch (tier) {
        case KdfTier::kNone: return "none";
        case KdfTier::kLow:  return "low";
        case KdfTier::kHigh: return "high";
    }
    return "unknown";
}

bool PeekTier(const uint8_t* blob, size_t blob_len, KdfTier& out) {
    if (!blob || blob_len < kTierEnd) return false;
    if (std::memcmp(blob, kMagic, 4) != 0) return false;
    size_t off = 4;
    uint32_t version = 0, tier = 0;
    if (!GetU32(blob, blob_len, off, version) || version != kVersion) return false;
    if (!GetU32(blob, blob_len, off, tier) || !IsValidTier(tier)) return false;
    out = static_cast<KdfTier>(tier);
    return true;
}

// Blob layout (v4):
//   magic[4] | version(u32) | kdf_tier(u32) | salt[16] | nonce[24] |
//   block_off(u32) | code_len(u32) | data_len(u32) | fw_root(u64) |
//   phys_to_op[256] | op_to_phys[256] | code[code_len] |
//   ciphertext[data_len + 16]
// Everything before `ciphertext` is the AEAD associated data (authenticated but
// not encrypted); `ciphertext` is AEAD(prog.data) — the diffused-key table bank.
//
// kdf_tier lives INSIDE the associated data, and that placement is load-bearing:
// it is what makes tier downgrade useless. Rewriting the field to kNone both
// changes the key DeriveKey produces and changes the AD the tag covers, so the
// tag fails for every passphrase — the attacker gets a cheap wrong answer, not a
// cheap guessing oracle. Moving this field out of the AD would break that.
std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase,
                          KdfTier tier) {
    EnsureSodium();

    std::vector<uint8_t> blob;
    blob.insert(blob.end(), kMagic, kMagic + 4);
    PutU32(blob, kVersion);
    PutU32(blob, static_cast<uint32_t>(tier));

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
    if (!DeriveKey(passphrase, blob.data() + salt_off, tier, key)) {
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

bool Unseal(const uint8_t* blob, size_t blob_len, const std::string& passphrase,
            vm::Program& out) {
    EnsureSodium();
    if (!blob) return false;

    size_t off = 0;
    if (blob_len < 4 || std::memcmp(blob, kMagic, 4) != 0) return false;
    off = 4;
    uint32_t version, tier_raw, block_off, code_len, data_len;
    uint64_t fw_root;
    if (!GetU32(blob, blob_len, off, version) || version != kVersion) return false;
    // Validate the tier before it can reach DeriveKey: an out-of-range value must
    // not select a cost, and a blob-supplied Argon2 arena size must never be
    // expressible at all (hence the closed enum).
    if (!GetU32(blob, blob_len, off, tier_raw) || !IsValidTier(tier_raw)) return false;
    const KdfTier tier = static_cast<KdfTier>(tier_raw);
    if (off + kSaltBytes + kNonceBytes > blob_len) return false;
    const size_t salt_off = off;
    off += kSaltBytes + kNonceBytes;
    if (!GetU32(blob, blob_len, off, block_off)) return false;
    if (!GetU32(blob, blob_len, off, code_len)) return false;
    if (!GetU32(blob, blob_len, off, data_len)) return false;
    if (!GetU64(blob, blob_len, off, fw_root)) return false;
    if (off + 512 > blob_len) return false;

    out = vm::Program();
    out.block_off = block_off;
    out.fw_root = fw_root;
    std::copy(blob + off, blob + off + 256, out.phys_to_op.begin());
    off += 256;
    std::copy(blob + off, blob + off + 256, out.op_to_phys.begin());
    off += 256;
    if (off + code_len > blob_len) return false;
    out.code.assign(blob + off, blob + off + code_len);
    off += code_len;

    // Everything from the start of the blob up to here is the associated data;
    // the remainder is ciphertext+tag and must be exactly data_len + kTagBytes.
    const size_t header_len = off;
    const size_t ct_len = static_cast<size_t>(data_len) + kTagBytes;
    if (header_len + ct_len != blob_len) return false;

    uint8_t key[kKeyBytes];
    if (!DeriveKey(passphrase, blob + salt_off, tier, key)) {
        sodium_memzero(key, sizeof key);
        return false;
    }

    // This resize value-initializes 400 KB that the AEAD immediately overwrites
    // (~0.2 ms). std::vector cannot be sized without that zero-fill before C++23's
    // resize_and_overwrite, and every alternative — a raw buffer plus an assign, a
    // no-init allocator on vm::Program::data — trades the fill for a copy or for
    // a nonstandard type that ripples through the VM. Left as-is deliberately.
    out.data.resize(data_len);
    unsigned long long pt_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        out.data.data(), &pt_len, nullptr,
        blob + header_len, ct_len,
        blob, header_len,                 // associated data = header
        blob + salt_off + kSaltBytes,     // nonce
        key);
    sodium_memzero(key, sizeof key);
    if (rc != 0) return false;  // wrong passphrase or tampered blob
    out.data.resize(static_cast<size_t>(pt_len));
    return true;
}

bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out) {
    return Unseal(blob.data(), blob.size(), passphrase, out);
}

}  // namespace storage
