#include "wbaes/wb_generator.h"

#include <vector>

#include "wbaes/aes_tables.h"
#include "wbaes/encodings.h"

namespace wbaes {

namespace {

// Inverse of ShiftRowsSrc: where does source position `src` land after ShiftRows?
int ShiftRowsDst(int src) {
    for (int dst = 0; dst < 16; ++dst)
        if (ShiftRowsSrc(dst) == src) return dst;
    return src;  // unreachable
}

// Build one type-IV nibble XOR table pair realising encOut(dec_A(a) ^ dec_B(b)),
// separately for the high and low nibble planes.
void BuildXor(const ByteEnc& encA, const ByteEnc& encB, const ByteEnc& encOut,
              XorTab& hi, XorTab& lo) {
    for (int a = 0; a < 16; ++a) {
        for (int b = 0; b < 16; ++b) {
            int idx = (a << 4) | b;
            hi[idx] = encOut.hi.enc(encA.hi.dec(a) ^ encB.hi.dec(b));
            lo[idx] = encOut.lo.enc(encA.lo.dec(a) ^ encB.lo.dec(b));
        }
    }
}

}  // namespace

std::unique_ptr<WhiteBox> GenerateWhiteBox(const Key128& key, uint64_t seed,
                                           WBLevel level) {
    auto wb = std::make_unique<WhiteBox>();
    wb->level = level;

    auto rk = KeyExpansion(key);
    Rng rng(seed);
    const bool randomize = (level != WBLevel::Naked);
    auto mkEnc = [&]() { return randomize ? RandomByteEnc(rng) : IdentityByteEnc(); };

    // --- Assign an encoding to every byte wire in the network. --------------
    // OUT[m][i]: encoding of round m's output byte i (== input decode of m+1).
    // TB[m][i] : encoding of T-box m output byte i (feeds Ty via ShiftRows).
    // TY[m][p][j]: encoding of Tyi(m,p) output lane j.
    // W1/W2[m][c][j]: encodings of the two intermediate XOR-tree sums.
    std::array<std::array<ByteEnc, 16>, 9> OUT, TB;
    std::array<std::array<std::array<ByteEnc, 4>, 16>, 9> TY;
    std::array<std::array<std::array<ByteEnc, 4>, 4>, 9> W1, W2;
    for (int m = 0; m < 9; ++m) {
        for (int i = 0; i < 16; ++i) {
            OUT[m][i] = mkEnc();
            TB[m][i] = mkEnc();
            for (int j = 0; j < 4; ++j) TY[m][i][j] = mkEnc();
        }
        for (int c = 0; c < 4; ++c)
            for (int j = 0; j < 4; ++j) {
                W1[m][c][j] = mkEnc();
                W2[m][c][j] = mkEnc();
            }
    }
    ByteEnc identity = IdentityByteEnc();

    // --- T-boxes for rounds 1..9 (indices 0..8). ----------------------------
    for (int m = 0; m < 9; ++m) {
        const uint8_t* km = &rk[16 * m];  // folds AES round key k_m
        for (int i = 0; i < 16; ++i) {
            const ByteEnc& inDec = (m == 0) ? identity : OUT[m - 1][i];
            for (int v = 0; v < 256; ++v) {
                uint8_t x = inDec.dec(static_cast<uint8_t>(v));
                uint8_t s = kSBox[x ^ km[i]];
                wb->tbox[m][i][v] = TB[m][i].enc(s);
            }
        }
    }

    // --- Final T-box (AES round 10, index 9): fold k9 in, k10 after ShiftRows.
    {
        const uint8_t* k9 = &rk[16 * 9];
        const uint8_t* k10 = &rk[16 * 10];
        for (int i = 0; i < 16; ++i) {
            const ByteEnc& inDec = OUT[8][i];
            int dst = ShiftRowsDst(i);  // where byte i lands after ShiftRows
            for (int v = 0; v < 256; ++v) {
                uint8_t x = inDec.dec(static_cast<uint8_t>(v));
                uint8_t s = kSBox[x ^ k9[i]];
                wb->tbox[9][i][v] = s ^ k10[dst];  // external encoding identity
            }
        }
    }

    // --- Tyi tables for rounds 1..9. ----------------------------------------
    for (int m = 0; m < 9; ++m) {
        for (int p = 0; p < 16; ++p) {
            int src = ShiftRowsSrc(p);
            const ByteEnc& inDec = TB[m][src];
            int row = p % 4;  // input's row within its MixColumns column
            for (int v = 0; v < 256; ++v) {
                uint8_t x = inDec.dec(static_cast<uint8_t>(v));
                auto four = Tyi(row, x);
                for (int j = 0; j < 4; ++j)
                    wb->ty[m][p][v][j] = TY[m][p][j].enc(four[j]);
            }
        }
    }

    // --- Type-IV XOR trees combining the four Tyi outputs per column. --------
    for (int m = 0; m < 9; ++m) {
        for (int c = 0; c < 4; ++c) {
            for (int j = 0; j < 4; ++j) {
                // step 0: TY[4c+0] ^ TY[4c+1] -> W1
                BuildXor(TY[m][4 * c + 0][j], TY[m][4 * c + 1][j], W1[m][c][j],
                         wb->xr[m][c][j][0][0], wb->xr[m][c][j][0][1]);
                // step 1: W1 ^ TY[4c+2] -> W2
                BuildXor(W1[m][c][j], TY[m][4 * c + 2][j], W2[m][c][j],
                         wb->xr[m][c][j][1][0], wb->xr[m][c][j][1][1]);
                // step 2: W2 ^ TY[4c+3] -> OUT[4c+j]
                BuildXor(W2[m][c][j], TY[m][4 * c + 3][j], OUT[m][4 * c + j],
                         wb->xr[m][c][j][2][0], wb->xr[m][c][j][2][1]);
            }
        }
    }

    return wb;
}

}  // namespace wbaes
