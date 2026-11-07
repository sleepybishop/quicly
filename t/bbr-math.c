#include "test.h"
#ifndef QUICLY_BBR_FORCE_PORTABLE_MATH
#define QUICLY_BBR_FORCE_PORTABLE_MATH
#endif
#include "../lib/bbr/math.h"

void test_bbr_math(void)
{
    static const struct {
        uint64_t a, b, divisor, expected;
    } cases[] = {
        {0, UINT64_MAX, 1, 0},
        {UINT64_MAX, 0, UINT64_MAX, 0},
        {7, 3, 2, 10},
        {UINT64_MAX, 1, 1, UINT64_MAX},
        {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX},
        {UINT64_MAX, UINT64_MAX, UINT64_MAX - 1, UINT64_MAX},
        {UINT64_MAX, UINT64_MAX, 1, UINT64_MAX},
        {UINT64_MAX, 2, 2, UINT64_MAX},
        {UINT64_MAX, 2, 3, UINT64_C(12297829382473034410)},
        {UINT64_C(1) << 32, UINT64_C(1) << 32, 1, UINT64_MAX},
        {UINT64_C(1) << 32, UINT64_C(1) << 32, 2, UINT64_C(1) << 63},
        {UINT64_MAX, UINT64_C(1000000000), UINT64_MAX, UINT64_C(1000000000)},
        {UINT64_C(1) << 63, UINT64_C(1) << 63, UINT64_MAX, UINT64_C(1) << 62},
        {UINT64_MAX, UINT64_C(102400), UINT64_C(277) * 120000, UINT64_C(56827514835976476)},
        {UINT64_MAX, UINT64_C(102400), 277, UINT64_MAX},
    };
    for (size_t i = 0; i != PTLS_ELEMENTSOF(cases); ++i) {
        ok(quicly_bbr_muldiv(cases[i].a, cases[i].b, cases[i].divisor) == cases[i].expected);
        ok(quicly_bbr_muldiv(cases[i].b, cases[i].a, cases[i].divisor) == cases[i].expected);
    }

#if defined(__SIZEOF_INT128__)
    /* exercise carries, remainders, and both BBR multipliers against a 128-bit reference */
    uint64_t state = UINT64_C(0x123456789abcdef);
    size_t mismatches = 0;
    for (size_t i = 0; i != 4096; ++i) {
        state = state * UINT64_C(6364136223846793005) + 1;
        uint64_t a = state;
        state = state * UINT64_C(6364136223846793005) + 1;
        uint64_t b = i % 3 == 0 ? UINT64_C(1000000000) : i % 3 == 1 ? UINT64_C(102400) : state;
        state = state * UINT64_C(6364136223846793005) + 1;
        uint64_t divisor = state | 1;
        __uint128_t quotient = (__uint128_t)a * b / divisor;
        uint64_t expected = quotient > UINT64_MAX ? UINT64_MAX : (uint64_t)quotient;
        mismatches += quicly_bbr_muldiv(a, b, divisor) != expected;
    }
    ok(mismatches == 0);
#endif
}
