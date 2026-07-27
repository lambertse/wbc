// opaque.h — opaque predicate primitive (Blazytko deck, "Opaque Predicate").
//
// An opaque-true predicate evaluates to a fixed truth value the obfuscator
// knows but a static analyzer must prove. We use the identity
//     x | ~x == 0xFFFFFFFF   (nonzero) for every x,
// which needs no multiplication (the VM has none) yet forces the analyst to
// reason about NOT/OR semantics. The assembler emits this to guard a junk block
// with an always-taken branch (see AssembleWhiteBox), inserting dead code and
// bogus control flow into the bytecode.
#ifndef WBVM_OBF_OPAQUE_H
#define WBVM_OBF_OPAQUE_H

#include <cstdint>

namespace obf {

// Reference value of the opaque-true predicate for testing: always 0xFFFFFFFF.
inline uint32_t OpaqueTrue(uint32_t x) { return x | ~x; }

}  // namespace obf

#endif  // WBVM_OBF_OPAQUE_H
