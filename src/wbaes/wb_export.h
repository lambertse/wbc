// wb_export.h — export a WhiteBox network as a flat table image.
//
// The image is the on-device format consumed by the freestanding runtime
// (freestanding/wb_stub.h); layout is defined once in
// freestanding/wb_table_layout.h. No VM bytecode is included — the device runs
// the table network directly, so the image carries only the diffused-key tables.
#ifndef WBVM_WBAES_WB_EXPORT_H
#define WBVM_WBAES_WB_EXPORT_H

#include <cstdint>
#include <vector>

#include "wbaes/wb_generator.h"

namespace wbaes {

// Serialize `wb` into a WBTB table image (header + tbox + ty + xr).
std::vector<uint8_t> ExportTableImage(const WhiteBox& wb);

}  // namespace wbaes

#endif  // WBVM_WBAES_WB_EXPORT_H
