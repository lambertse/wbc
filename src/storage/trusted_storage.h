// trusted_storage.h — seal a compiled white-box Program into an at-rest blob.
//
// This is the "trusted storage" wrapper around the white-box VM. On disk:
//   * the table bank (which holds the diffused key) is never in plaintext — it
//     is stream-sealed under a passphrase-derived storage key;
//   * the bytecode keystream is stored only as an 8-byte seed, not literally;
//   * an integrity tag over the program logic (code + opcode maps + seeds) is
//     folded into the data-decrypt key, so any tamper with the VM code makes
//     the tables decrypt to garbage and the cipher output goes wrong
//     (anti-tamper by binding, not by a checked-then-ignored MAC).
//
// Honesty: the passphrase KDF here is a lightweight hash, not a real PBKDF, and
// the whole scheme raises the bar for *static* extraction rather than providing
// cryptographic key secrecy — see README.
#ifndef WBVM_STORAGE_TRUSTED_STORAGE_H
#define WBVM_STORAGE_TRUSTED_STORAGE_H

#include <cstdint>
#include <string>
#include <vector>

#include "vm/vm.h"

namespace storage {

// Serialize + seal `prog` under `passphrase`. Returns the blob bytes.
std::vector<uint8_t> Seal(const vm::Program& prog, const std::string& passphrase);

// Parse + unseal a blob under `passphrase` into `out`. Returns false on a
// malformed blob. NOTE: a wrong passphrase or a tampered blob does not error —
// it yields a Program that runs but produces wrong ciphertext (by design).
bool Unseal(const std::vector<uint8_t>& blob, const std::string& passphrase,
            vm::Program& out);

}  // namespace storage

#endif  // WBVM_STORAGE_TRUSTED_STORAGE_H
