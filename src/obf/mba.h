// mba.h — Mixed Boolean-Arithmetic identities (Blazytko deck, "mixed_boolean").
//
// These are exact integer identities on 32-bit words. The assembler emits the
// right-hand sides as VM bytecode so that the index arithmetic inside the
// white-box interpreter (nibble split/pack) is expressed as tangled
// arithmetic+boolean sequences instead of single ops.
//
// IMPORTANT: MBA is applied to the *emitted bytecode*, not to the C++ handler
// source — a C++ optimizer would fold source-level MBA straight back to the
// primitive op. The VM executes exactly the ops emitted, so the obfuscation
// survives. What it hides is the index arithmetic; the cipher's data-flow XORs
// are table lookups, not VM ops, so MBA does not conceal those.
//
// The functions here are the reference oracle for test_obf; they must equal the
// primitive operator for all inputs.
#ifndef WBVM_OBF_MBA_H
#define WBVM_OBF_MBA_H

#include <cstdint>

namespace obf {

// x ^ y == (x | y) - (x & y)
inline uint32_t MbaXor(uint32_t x, uint32_t y) { return (x | y) - (x & y); }
// x | y == (x ^ y) + (x & y)
inline uint32_t MbaOr(uint32_t x, uint32_t y) { return (x ^ y) + (x & y); }
// x & y == (x | y) - (x ^ y)
inline uint32_t MbaAnd(uint32_t x, uint32_t y) { return (x | y) - (x ^ y); }
// x + y == (x ^ y) + 2*(x & y)
inline uint32_t MbaAdd(uint32_t x, uint32_t y) { return (x ^ y) + ((x & y) << 1); }

}  // namespace obf

#endif  // WBVM_OBF_MBA_H
