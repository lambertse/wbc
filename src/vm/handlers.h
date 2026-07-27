// handlers.h — one execution handler per logical opcode, plus the dispatch table.
//
// The dispatcher (vm.cpp) fetches a physical opcode byte, maps it back to a
// logical Op, and calls Handlers()[op]. This mirrors the fetch-decode-execute /
// handler-table structure of real VM-based obfuscators.
#ifndef WBVM_VM_HANDLERS_H
#define WBVM_VM_HANDLERS_H

#include <array>

#include "vm/isa.h"
#include "vm/vm.h"

namespace vm {

using Handler = void (*)(VMContext&);

// Handler table indexed by logical Op.
const std::array<Handler, kOpCount>& Handlers();

}  // namespace vm

#endif  // WBVM_VM_HANDLERS_H
