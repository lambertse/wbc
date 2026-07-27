/* wb_table_layout.h — canonical layout of the exported white-box table image.
 *
 * Single source of truth shared by the host-side exporter (C++,
 * src/wbaes/wb_export.cpp) and the freestanding device runtime (wb_stub.h).
 * Pure C, freestanding-safe: only <stdint.h>/<stddef.h> (guaranteed freestanding
 * headers), no libc, no allocation.
 *
 * Image = 12-byte header followed by three raw table regions in this fixed
 * order. All indices are the same as the C++ white-box (see wb_generator.cpp).
 *
 *   [0]  magic 'W','B','T','B'
 *   [4]  u32 version (LE)
 *   [8]  u32 rounds  (LE, = 10, informational)
 *   [12] tbox region : 10*16*256 bytes
 *        ty   region : 9*16*256*4 bytes
 *        xr   region : 9*4*4*3*2*256 bytes
 */
#ifndef WB_TABLE_LAYOUT_H
#define WB_TABLE_LAYOUT_H

#include <stddef.h>
#include <stdint.h>

#define WBTB_MAGIC0 'W'
#define WBTB_MAGIC1 'B'
#define WBTB_MAGIC2 'T'
#define WBTB_MAGIC3 'B'
#define WBTB_VERSION 1u

#define WBTB_HEADER   12u
#define WBTB_TBOX_OFF (WBTB_HEADER)
#define WBTB_TBOX_SIZE (10u * 16u * 256u)             /* 40960  */
#define WBTB_TY_OFF   (WBTB_TBOX_OFF + WBTB_TBOX_SIZE)
#define WBTB_TY_SIZE  (9u * 16u * 256u * 4u)          /* 147456 */
#define WBTB_XR_OFF   (WBTB_TY_OFF + WBTB_TY_SIZE)
#define WBTB_XR_SIZE  (9u * 4u * 4u * 3u * 2u * 256u) /* 221184 */
#define WBTB_IMAGE_SIZE (WBTB_XR_OFF + WBTB_XR_SIZE)  /* 409612 */

/* Row-pointer accessors into a table image base `T` (const uint8_t*). */
#define WB_TBOX_ROW(T, m, i) \
    ((T) + WBTB_TBOX_OFF + (size_t)((m) * 16 + (i)) * 256u)
#define WB_TY_ROW(T, m, p) \
    ((T) + WBTB_TY_OFF + (size_t)((m) * 16 + (p)) * 256u * 4u)
#define WB_XR_ROW(T, m, c, j, step, half)                                     \
    ((T) + WBTB_XR_OFF +                                                      \
     (size_t)(((((m) * 4 + (c)) * 4 + (j)) * 3 + (step)) * 2 + (half)) * 256u)

#endif /* WB_TABLE_LAYOUT_H */
