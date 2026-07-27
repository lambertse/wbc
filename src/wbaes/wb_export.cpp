#include "wbaes/wb_export.h"

#include <cstring>

extern "C" {
#include "wb_table_layout.h"
}

namespace wbaes {

std::vector<uint8_t> ExportTableImage(const WhiteBox& wb) {
    std::vector<uint8_t> img(WBTB_IMAGE_SIZE, 0);
    img[0] = WBTB_MAGIC0; img[1] = WBTB_MAGIC1;
    img[2] = WBTB_MAGIC2; img[3] = WBTB_MAGIC3;
    auto put32 = [&](uint32_t off, uint32_t v) {
        img[off] = v & 0xFF; img[off + 1] = (v >> 8) & 0xFF;
        img[off + 2] = (v >> 16) & 0xFF; img[off + 3] = (v >> 24) & 0xFF;
    };
    put32(4, WBTB_VERSION);
    put32(8, 10);  // rounds

    // T-boxes: [10][16][256]
    for (int m = 0; m < 10; ++m)
        for (int i = 0; i < 16; ++i)
            std::memcpy(&img[WBTB_TBOX_OFF + (size_t)(m * 16 + i) * 256],
                        wb.tbox[m][i].data(), 256);
    // Tyi: [9][16][256][4]
    for (int m = 0; m < 9; ++m)
        for (int p = 0; p < 16; ++p)
            for (int v = 0; v < 256; ++v)
                std::memcpy(&img[WBTB_TY_OFF + ((size_t)(m * 16 + p) * 256 + v) * 4],
                            wb.ty[m][p][v].data(), 4);
    // Type-IV XOR: [9][4][4][3][2][256]
    for (int m = 0; m < 9; ++m)
        for (int c = 0; c < 4; ++c)
            for (int j = 0; j < 4; ++j)
                for (int step = 0; step < 3; ++step)
                    for (int half = 0; half < 2; ++half) {
                        size_t row = (size_t)((((m * 4 + c) * 4 + j) * 3 + step) * 2 + half);
                        std::memcpy(&img[WBTB_XR_OFF + row * 256],
                                    wb.xr[m][c][j][step][half].data(), 256);
                    }
    return img;
}

}  // namespace wbaes
