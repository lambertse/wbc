// test_util.h — tiny dependency-free test harness (no gtest available).
#ifndef WBVM_TESTS_TEST_UTIL_H
#define WBVM_TESTS_TEST_UTIL_H

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace test {

inline int& failures() {
    static int f = 0;
    return f;
}

inline std::string ToHex(const uint8_t* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(h[p[i] >> 4]);
        s.push_back(h[p[i] & 0xF]);
    }
    return s;
}

template <size_t N>
std::array<uint8_t, N> FromHex(const std::string& hex) {
    std::array<uint8_t, N> out{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (size_t i = 0; i < N && 2 * i + 1 < hex.size(); ++i) {
        out[i] = static_cast<uint8_t>((nib(hex[2 * i]) << 4) | nib(hex[2 * i + 1]));
    }
    return out;
}

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++::test::failures();                                         \
        }                                                                 \
    } while (0)

#define CHECK_EQ_HEX(actual_ptr, actual_len, expected_hex)                  \
    do {                                                                    \
        std::string a = ::test::ToHex((actual_ptr), (actual_len));          \
        std::string e = (expected_hex);                                     \
        if (a != e) {                                                       \
            std::printf("  FAIL %s:%d: got %s want %s\n", __FILE__,         \
                        __LINE__, a.c_str(), e.c_str());                    \
            ++::test::failures();                                           \
        }                                                                   \
    } while (0)

inline int Report(const char* name) {
    if (test::failures() == 0) {
        std::printf("[PASS] %s\n", name);
        return 0;
    }
    std::printf("[FAIL] %s (%d failures)\n", name, test::failures());
    return 1;
}

}  // namespace test

#endif  // WBVM_TESTS_TEST_UTIL_H
