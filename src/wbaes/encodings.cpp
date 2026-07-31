#include "encodings.h"

#include <utility>  // std::swap

namespace wbaes {

Nibble IdentityNibble() {
    Nibble n;
    for (int i = 0; i < 16; ++i) n.fwd[i] = n.inv[i] = static_cast<uint8_t>(i);
    return n;
}

Nibble RandomNibble(Rng& rng) {
    Nibble n;
    for (int i = 0; i < 16; ++i) n.fwd[i] = static_cast<uint8_t>(i);
    // Fisher-Yates shuffle.
    for (int i = 15; i > 0; --i) {
        int j = static_cast<int>(rng.next() % static_cast<uint64_t>(i + 1));
        std::swap(n.fwd[i], n.fwd[j]);
    }
    for (int i = 0; i < 16; ++i) n.inv[n.fwd[i]] = static_cast<uint8_t>(i);
    return n;
}

ByteEnc IdentityByteEnc() {
    ByteEnc b;
    b.hi = IdentityNibble();
    b.lo = IdentityNibble();
    return b;
}

ByteEnc RandomByteEnc(Rng& rng) {
    ByteEnc b;
    b.hi = RandomNibble(rng);
    b.lo = RandomNibble(rng);
    return b;
}

}  // namespace wbaes
