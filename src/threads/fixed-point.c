#include <stdint.h>
#include "threads/fixed-point.h"

fixed_t add_fp(fixed_t x, fixed_t y)
{
    return x + y;
}

fixed_t subtract_fp(fixed_t x, fixed_t y)
{
    return x - y;
}

fixed_t add_fp_int(fixed_t x, int n)
{
    return x + INT_TO_FIXED(n);
}

fixed_t subtract_fp_int(fixed_t x, int n)
{
    return x - INT_TO_FIXED(n);
}

fixed_t product_fp_int(fixed_t x, int n)
{
    return x * n;
}

fixed_t quotient_fp_int(fixed_t x, int n)
{
    return x / n;
}

fixed_t product_fp(fixed_t x, fixed_t y)
{
    return ((int64_t)x) * y / F;
}

fixed_t quotient_fp(fixed_t x, fixed_t y)
{
    return ((int64_t)x * F) / y;
}

fixed_t fraction_to_fp(int numerator, int denominator)
{
    return ((int64_t)numerator * F + denominator / 2) / denominator;
}
