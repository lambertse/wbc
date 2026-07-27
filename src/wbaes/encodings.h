// encodings.h — internal encodings for the white-box network.
//
// Every intermediate byte in the Chow network is hidden behind an 8-bit
// encoding formed by concatenating two independent 4-bit (nibble) bijections.
// The nibble split is what makes XOR realizable as small lookup tables
// (Chow "type IV" tables): XORing two encoded bytes = two nibble-table lookups.
//
// At WBLevel::Naked every encoding is the identity, so the network computes
// plain AES (the correctness anchor). At higher levels the encodings are random
// bijections seeded by a key/seed, and consecutive tables are built so the
// encodings cancel.
#ifndef WBVM_WBAES_ENCODINGS_H
#define WBVM_WBAES_ENCODINGS_H

#include <array>
#include <cstdint>

namespace wbaes {

// A bijection on the 4-bit space {0..15} plus its inverse.
struct Nibble {
    std::array<uint8_t, 16> fwd{};
    std::array<uint8_t, 16> inv{};
    uint8_t enc(uint8_t x) const { return fwd[x & 0xF]; }
    uint8_t dec(uint8_t y) const { return inv[y & 0xF]; }
};

// An 8-bit encoding = high nibble bijection || low nibble bijection.
struct ByteEnc {
    Nibble hi, lo;
    uint8_t enc(uint8_t x) const {
        return static_cast<uint8_t>((hi.enc(x >> 4) << 4) | lo.enc(x & 0xF));
    }
    uint8_t dec(uint8_t y) const {
        return static_cast<uint8_t>((hi.dec(y >> 4) << 4) | lo.dec(y & 0xF));
    }
};

// Deterministic PRNG (splitmix64) so a (key, seed) reproduces the same tables.
class Rng {
public:
    explicit Rng(uint64_t seed) : state_(seed) {}
    uint64_t next() {
        uint64_t z = (state_ += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
private:
    uint64_t state_;
};

Nibble IdentityNibble();
Nibble RandomNibble(Rng& rng);
ByteEnc IdentityByteEnc();
ByteEnc RandomByteEnc(Rng& rng);

}  // namespace wbaes

#endif  // WBVM_WBAES_ENCODINGS_H
