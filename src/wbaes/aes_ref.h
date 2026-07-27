// aes_ref.h — Textbook reference AES-128 encryption.
//
// This exists ONLY as a correctness oracle: the white-box construction and the
// VM must reproduce this function's output on the FIPS-197 test vector and on
// random blocks. It is intentionally simple and not constant-time / not for
// production use.
#ifndef WBVM_WBAES_AES_REF_H
#define WBVM_WBAES_AES_REF_H

#include <array>
#include <cstdint>

namespace wbaes {

using Block = std::array<uint8_t, 16>;   // AES state / block (column-major)
using Key128 = std::array<uint8_t, 16>;

// The AES S-box and its inverse, exposed so the white-box T-box builder can
// reuse them instead of recomputing.
extern const std::array<uint8_t, 256> kSBox;

// Expand a 128-bit key into 11 round keys (176 bytes).
std::array<uint8_t, 176> KeyExpansion(const Key128& key);

// Encrypt a single 16-byte block with AES-128. Reference oracle.
Block AesEncryptBlock(const Block& in, const Key128& key);

}  // namespace wbaes

#endif  // WBVM_WBAES_AES_REF_H
