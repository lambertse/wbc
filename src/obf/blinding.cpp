#include "obf/blinding.h"

#include <utility>  // std::swap

namespace obf {

OpcodeBlinding BuildOpcodeBlinding(wbaes::Rng& rng, int op_count,
                                   int min_variants, int max_variants) {
    // A random permutation of all 256 byte values; we hand them out in order so
    // no two logical opcodes ever share a physical byte.
    std::array<uint8_t, 256> perm{};
    for (int i = 0; i < 256; ++i) perm[i] = static_cast<uint8_t>(i);
    for (int i = 255; i > 0; --i) {
        int j = static_cast<int>(rng.next() % static_cast<uint64_t>(i + 1));
        std::swap(perm[i], perm[j]);
    }

    OpcodeBlinding ob;
    ob.phys_to_op.fill(0xFF);
    ob.op_to_phys.fill(0);
    ob.variants.resize(op_count);

    int span = max_variants - min_variants + 1;
    int next = 0;
    for (int op = 0; op < op_count; ++op) {
        int count = min_variants + static_cast<int>(rng.next() % static_cast<uint64_t>(span));
        for (int k = 0; k < count && next < 256; ++k) {
            uint8_t phys = perm[next++];
            ob.variants[op].push_back(phys);
            ob.phys_to_op[phys] = static_cast<uint8_t>(op);
        }
        // Guarantee at least one variant even if the byte space ran out.
        if (ob.variants[op].empty() && next < 256) {
            uint8_t phys = perm[next++];
            ob.variants[op].push_back(phys);
            ob.phys_to_op[phys] = static_cast<uint8_t>(op);
        }
        ob.op_to_phys[op] = ob.variants[op].front();
    }
    return ob;
}

}  // namespace obf
