// trusted_storage.h — seal a compiled white-box Program into an at-rest blob.
//
// This is the "trusted storage" wrapper around the white-box VM. On disk the
// table bank (which holds the diffused key) is encrypted with a vetted AEAD
// (XChaCha20-Poly1305) under a key derived from the passphrase with a real,
// memory-hard KDF (Argon2id) and a random per-blob salt. The rest of the
// program logic (magic, version, sizes, fw_root, opcode maps, bytecode) is
// bound as the AEAD's associated data, so any tamper — to the tables OR to the
// logic — fails authentication.
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

// Serialize + seal `prog` under `passphrase`. Each call uses a fresh random
// salt and nonce, so sealing the same program twice yields different bytes.
// Throws std::bad_alloc if the KDF cannot allocate its memory arena.
std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase);

// Parse + unseal a blob under `passphrase` into `out`. Returns false on a
// malformed blob, a wrong passphrase, OR a tampered blob (AEAD authentication
// failure) — unlike the previous construction, a wrong key no longer "opens"
// to a wrong-output program.
bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out);

}  // namespace storage

#endif  // WBVM_STORAGE_TRUSTED_STORAGE_H
