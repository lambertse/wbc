#include "aes_ref.h"

#include "gf256.h"

namespace wbaes {

namespace {

// Build the AES S-box from first principles: inverse in GF(2^8) followed by the
// affine transform. Computing it (rather than hardcoding 256 magic bytes) keeps
// the file auditable and ties it to gf256.
std::array<uint8_t, 256> BuildSBox() {
    std::array<uint8_t, 256> sbox{};
    for (int i = 0; i < 256; ++i) {
        uint8_t x = gf::inv(static_cast<uint8_t>(i));
        uint8_t s = x;
        // s = x ^ (x<<<1) ^ (x<<<2) ^ (x<<<3) ^ (x<<<4) ^ 0x63
        for (int r = 1; r <= 4; ++r) {
            s ^= static_cast<uint8_t>((x << r) | (x >> (8 - r)));
        }
        s ^= 0x63;
        sbox[i] = s;
    }
    return sbox;
}

const uint8_t kRcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                           0x20, 0x40, 0x80, 0x1B, 0x36};

}  // namespace

const std::array<uint8_t, 256> kSBox = BuildSBox();

std::array<uint8_t, 176> KeyExpansion(const Key128& key) {
    std::array<uint8_t, 176> rk{};
    for (int i = 0; i < 16; ++i) rk[i] = key[i];
    int words = 4;  // 4 words already filled (the key)
    uint8_t tmp[4];
    for (int w = 4; w < 44; ++w) {
        int prev = (w - 1) * 4;
        for (int j = 0; j < 4; ++j) tmp[j] = rk[prev + j];
        if (w % 4 == 0) {
            // RotWord
            uint8_t t = tmp[0];
            tmp[0] = tmp[1]; tmp[1] = tmp[2]; tmp[2] = tmp[3]; tmp[3] = t;
            // SubWord
            for (int j = 0; j < 4; ++j) tmp[j] = kSBox[tmp[j]];
            tmp[0] ^= kRcon[w / 4];
        }
        int base = w * 4;
        int back = (w - 4) * 4;
        for (int j = 0; j < 4; ++j) rk[base + j] = rk[back + j] ^ tmp[j];
        (void)words;
    }
    return rk;
}

namespace {

void AddRoundKey(Block& s, const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}

void SubBytes(Block& s) {
    for (auto& b : s) b = kSBox[b];
}

// State is column-major: byte index = row + 4*col.
void ShiftRows(Block& s) {
    Block t = s;
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
        }
    }
    s = t;
}

void MixColumns(Block& s) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a0 = s[4 * c + 0], a1 = s[4 * c + 1];
        uint8_t a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        s[4 * c + 0] = gf::mul(a0, 2) ^ gf::mul(a1, 3) ^ a2 ^ a3;
        s[4 * c + 1] = a0 ^ gf::mul(a1, 2) ^ gf::mul(a2, 3) ^ a3;
        s[4 * c + 2] = a0 ^ a1 ^ gf::mul(a2, 2) ^ gf::mul(a3, 3);
        s[4 * c + 3] = gf::mul(a0, 3) ^ a1 ^ a2 ^ gf::mul(a3, 2);
    }
}

}  // namespace

Block AesEncryptBlock(const Block& in, const Key128& key) {
    auto rk = KeyExpansion(key);
    Block s = in;
    AddRoundKey(s, &rk[0]);
    for (int round = 1; round <= 9; ++round) {
        SubBytes(s);
        ShiftRows(s);
        MixColumns(s);
        AddRoundKey(s, &rk[16 * round]);
    }
    SubBytes(s);
    ShiftRows(s);
    AddRoundKey(s, &rk[16 * 10]);
    return s;
}

}  // namespace wbaes
