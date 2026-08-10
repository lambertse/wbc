// trusted_storage.h — seal a compiled white-box Program into an at-rest blob.
//
// This is the "trusted storage" wrapper around the white-box VM. On disk the
// table bank (which holds the diffused key) is encrypted with a vetted AEAD
// (XChaCha20-Poly1305) under a key derived from the passphrase and a random
// per-blob salt. The rest of the program logic (magic, version, KDF tier,
// sizes, fw_root, opcode maps, bytecode) is bound as the AEAD's associated
// data, so any tamper — to the tables OR to the logic — fails authentication.
//
// The key derivation is a per-blob CHOICE, not a constant: see KdfTier below.
// Argon2id (memory-hard, the kLow/kHigh tiers) is what defuses offline
// guessing of a human passphrase; HKDF (kNone) is the correct and much cheaper
// answer when the passphrase is already a high-entropy machine secret.
//
// This replaces an earlier home-rolled construction (SplitMix64 XOR keystream +
// unkeyed FNV integrity tag) which had no KDF, no per-blob salt/nonce, and a
// forgeable tag. See the project README's threat-model section. In the
// white-box threat model an
// attacker who runs the field binary has the passphrase, so the seal's role is
// to protect the blob AT REST and raise the offline-extraction bar; its durable
// value comes with hardware-backed key binding (docs, P2.4).
#ifndef WBVM_STORAGE_TRUSTED_STORAGE_H
#define WBVM_STORAGE_TRUSTED_STORAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include "vm/vm.h"

namespace storage {

// ---- KDF cost tier ---------------------------------------------------------
//
// Which key-derivation the seal uses. Recorded IN THE BLOB (inside the AEAD
// associated data), not fixed at compile time, so any runtime can open any
// blob and a deployed blob's cost is auditable after the fact.
//
// The tier is a closed enum rather than raw ops/mem integers on purpose: a
// blob claiming, say, 4 GiB of Argon2 memory would be an OOM handed to us by
// an attacker. A finite legal set makes validation a range check.
//
// Argon2id defends against GUESSING the passphrase. That is worth ~250 ms only
// when there is something to guess. When the passphrase is a high-entropy
// machine-generated secret — and especially when it ships alongside the blob,
// as in a packed .so whose loader carries its own passphrase — nothing is
// guessed, and a memory-hard KDF buys nothing for its cost. Hence kNone.
enum class KdfTier : uint32_t {
    // HKDF-SHA256. Microseconds. SOUND ONLY for a passphrase carrying >= 128
    // bits of uniformly random machine-generated entropy. If a human can type
    // it, this tier is a full break of the seal's offline-guessing resistance.
    kNone = 0,
    // Argon2id, 16 MiB / 2 passes. A speed bump without the 64 MiB arena.
    kLow = 1,
    // Argon2id, 64 MiB / 2 passes — libsodium's INTERACTIVE tier. The right
    // choice for a human-chosen passphrase that does NOT ship with the blob.
    kHigh = 2,
};

// Argon2id cost for a tier. `ops == 0 && mem == 0` means "not Argon2id at all"
// (kNone, which uses HKDF); callers that time or report the KDF should treat
// that as the HKDF path rather than assuming Argon2id.
struct KdfParams {
    unsigned long long ops;
    size_t mem;
};

// Exported so callers (notably bench/wb_bench.cpp) can report the cost of the
// tier a given blob actually uses instead of duplicating the constants — that
// duplication was a live drift hazard while the parameters were compile-time.
KdfParams ParamsForTier(KdfTier tier);

// True if `v` is one of the enumerators above. Blob-supplied values MUST pass
// this before being used.
bool IsValidTier(uint32_t v);

// Human-readable tier name ("none" / "low" / "high"), never NULL.
const char* TierName(KdfTier tier);

// Read the KDF tier from a blob header without deriving anything — no KDF cost.
// Returns false if the blob is too short, not a WBTS blob, the wrong version,
// or carries an out-of-range tier.
bool PeekTier(const uint8_t* blob, size_t blob_len, KdfTier& out);

// Serialize + seal `prog` under `passphrase` at `tier`. Each call uses a fresh
// random salt and nonce, so sealing the same program twice yields different
// bytes. Throws std::bad_alloc if the KDF cannot allocate its memory arena.
std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase,
                          KdfTier tier);

// Parse + unseal a blob under `passphrase` into `out`. The tier comes from the
// blob. Returns false on a malformed blob, a wrong passphrase, OR a tampered
// blob (AEAD authentication failure) — unlike the previous construction, a
// wrong key no longer "opens" to a wrong-output program.
//
// A downgrade attack does not work: the tier is inside the associated data, so
// flipping it both changes the derived key and changes the AD, and the tag
// fails whatever the passphrase was. The cheap failure is not an oracle.
bool Unseal(const uint8_t* blob, size_t blob_len, const std::string& passphrase,
            vm::Program& out);

// Convenience overload. The pointer+length form above avoids copying the whole
// blob (~455 KB) just to satisfy a vector parameter.
bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out);

}  // namespace storage

#endif  // WBVM_STORAGE_TRUSTED_STORAGE_H
