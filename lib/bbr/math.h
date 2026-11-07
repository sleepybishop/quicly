/* exact, saturating arithmetic shared by the BBR adapter and delivery sampler */
#ifndef quicly_bbr_math_h
#define quicly_bbr_math_h

#include <stdint.h>

/* return min(floor(a * b / divisor), UINT64_MAX); divisor must be nonzero */
static inline uint64_t quicly_bbr_muldiv(uint64_t a, uint64_t b, uint64_t divisor)
{
#if defined(__SIZEOF_INT128__) && !defined(QUICLY_BBR_FORCE_PORTABLE_MATH)
    __uint128_t quotient = (__uint128_t)a * b / divisor;
    return quotient > UINT64_MAX ? UINT64_MAX : (uint64_t)quotient;
#else
    uint64_t low = (uint64_t)(uint32_t)a * (uint32_t)b;
    uint64_t cross1 = (a >> 32) * (uint32_t)b, cross2 = (uint32_t)a * (b >> 32);
    uint64_t high = (a >> 32) * (b >> 32) + (cross1 >> 32) + (cross2 >> 32);
    uint64_t previous = low;
    low += cross1 << 32;
    high += low < previous;
    previous = low;
    low += cross2 << 32;
    high += low < previous;

    if (high >= divisor)
        return UINT64_MAX;
    if (high == 0)
        return low / divisor;

    /* quotient fits in 64 bits; shift one dividend bit into the remainder at a time */
    uint64_t quotient = 0, remainder = high;
    for (unsigned bit = 64; bit-- != 0;) {
        int carry = (remainder >> 63) != 0;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= UINT64_C(1) << bit;
        }
    }
    return quotient;
#endif
}

#endif
