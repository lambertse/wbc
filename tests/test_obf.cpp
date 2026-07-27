// Milestone D: verify every obfuscation primitive is semantics-preserving
// before it is trusted inside the emitter. MBA identities are a classic bug
// source, so they are checked over the full 32-bit space by random sampling.
#include "test_util.h"
#include "obf/blinding.h"
#include "obf/mba.h"
#include "obf/opaque.h"
#include "wbaes/encodings.h"

int main() {
    wbaes::Rng rng(0xC0DEC0DEull);

    // MBA identities must equal the primitive operator for all inputs.
    for (int i = 0; i < 200000; ++i) {
        uint32_t x = static_cast<uint32_t>(rng.next());
        uint32_t y = static_cast<uint32_t>(rng.next());
        CHECK(obf::MbaXor(x, y) == (x ^ y));
        CHECK(obf::MbaOr(x, y) == (x | y));
        CHECK(obf::MbaAnd(x, y) == (x & y));
        CHECK(obf::MbaAdd(x, y) == (x + y));
        if (test::failures()) break;
    }

    // Opaque-true predicate is nonzero for every input (guards are always taken).
    for (int i = 0; i < 100000; ++i) {
        uint32_t x = static_cast<uint32_t>(rng.next());
        CHECK(obf::OpaqueTrue(x) == 0xFFFFFFFFu);
        if (test::failures()) break;
    }

    // Handler duplication: variants are disjoint and decode back to their op.
    wbaes::Rng brng(7);
    auto ob = obf::BuildOpcodeBlinding(brng, 19, 3, 5);
    std::array<int, 256> owner{};
    owner.fill(-1);
    for (int op = 0; op < 19; ++op) {
        CHECK(!ob.variants[op].empty());
        for (uint8_t phys : ob.variants[op]) {
            CHECK(ob.phys_to_op[phys] == op);
            CHECK(owner[phys] == -1);  // no physical byte shared between opcodes
            owner[phys] = op;
        }
    }

    return test::Report("test_obf");
}
