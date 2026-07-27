/* selftest.c — compile-only proof that the device runtime is freestanding.
 * Built with -ffreestanding -fno-builtin -nostdlib; must not pull in libc.
 * (Correctness is verified separately by tests/test_stub.cpp.) */
#include "wb_stub.h"

/* Referenced from nowhere at link time; exists so the header's static inline
 * functions are actually instantiated and codegen'd under freestanding flags. */
void wbstub_selftest(const uint8_t *tables, const uint8_t *in, uint8_t *out,
                     const uint8_t *iv, uint32_t len) {
    wbstub_encrypt_block(tables, in, out);
    wbstub_ctr_xcrypt(tables, iv, in, out, len);
}
