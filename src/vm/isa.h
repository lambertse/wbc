// isa.h — instruction set for the obfuscation VM.
//
// A small register machine with a Harvard-style split between code memory and
// data memory (see vm.h). The ISA is deliberately generic: it has no
// crypto-specific opcodes, so a static reverse-engineer sees only table loads,
// XORs and shifts over an encoded bytecode — not AES. The white-box is compiled
// down to this ISA by the assembler.
//
// Registers are 32-bit (used as scalar values and as data-memory addresses).
// Encodings below are the *logical* opcodes; the assembler remaps them through
// a per-program permutation and keystream-encodes the byte stream, so these
// numeric values are not what appears in a compiled program on disk.
#ifndef WBVM_VM_ISA_H
#define WBVM_VM_ISA_H

#include <cstdint>

namespace vm {

// 32 registers. Was 16, raised so the emitter can keep the four post-ShiftRows
// Tyi indices of a column live across all four output lanes instead of
// recomputing them per lane. Widening is safe and format-compatible in itself:
// operands stay one byte, and handlers.cpp masks every register index with
// kNumRegs-1, so a tampered operand still cannot escape the register file.
constexpr int kNumRegs = 32;

enum class Op : uint8_t {
    HALT = 0,   // stop the VM
    LDI,        // rd, imm32          : reg[rd] = imm32
    MOV,        // rd, rs             : reg[rd] = reg[rs]
    LDB,        // rd, rbase, roff    : reg[rd] = data[reg[rbase] + reg[roff]] (zero-ext byte)
    STB,        // rbase, roff, rs    : data[reg[rbase] + reg[roff]] = reg[rs] & 0xFF
    XOR,        // rd, ra, rb         : reg[rd] = reg[ra] ^ reg[rb]
    AND,        // rd, ra, rb         : reg[rd] = reg[ra] & reg[rb]
    OR,         // rd, ra, rb         : reg[rd] = reg[ra] | reg[rb]
    ADD,        // rd, ra, rb         : reg[rd] = reg[ra] + reg[rb]
    SUB,        // rd, ra, rb         : reg[rd] = reg[ra] - reg[rb]  (MBA building block)
    NOT,        // rd, ra             : reg[rd] = ~reg[ra]           (MBA / opaque predicates)
    SHL,        // rd, ra, imm8       : reg[rd] = reg[ra] << imm8
    SHR,        // rd, ra, imm8       : reg[rd] = reg[ra] >> imm8
    PUSH,       // rs                 : stack push reg[rs]
    POP,        // rd                 : reg[rd] = stack pop
    JMP,        // imm32              : vip = imm32 (code offset)
    JZ,         // rc, imm32          : if reg[rc]==0 vip = imm32
    JNZ,        // rc, imm32          : if reg[rc]!=0 vip = imm32
    DECJNZ,     // rc, imm32          : if (--reg[rc])!=0 vip = imm32  (loop)
    // Immediate-base data access. Every table lookup and every scratch access
    // has a CONSTANT base address, which previously cost a separate 6-byte
    // `LDI RBASE, <const>` before each 4-byte LDB/STB. Folding the base into the
    // access replaces 10 bytes and 2 instructions with 7 bytes and 1. Roughly
    // 3k of the ~13k instructions per block were those LDIs.
    LDBI,       // rd, imm32, roff    : reg[rd] = data[imm32 + reg[roff]]
    STBI,       // imm32, roff, rs    : data[imm32 + reg[roff]] = reg[rs] & 0xFF
    kCount
};

constexpr int kOpCount = static_cast<int>(Op::kCount);

// Longest encoding of a single instruction, in bytes: LDBI/STBI = opcode + reg +
// imm32 + reg. The decode schedule reseeds its keystream per instruction, so any
// future opcode longer than this needs fw_schedule.h revisited, not just a
// bigger buffer. The assembler asserts against it.
constexpr uint32_t kMaxInstrBytes = 7;

}  // namespace vm

#endif  // WBVM_VM_ISA_H
