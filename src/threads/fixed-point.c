#include <stdint.h>;
#define FRACTION 14
#define F 1 << FRACTION
#define INT_TO_FIXED(n) n * F
#define ROUND_TO_ZERO(x) x / F
#define ROUND_TO_NEAREST(x) if (x >= 0) {(x + F/2)} else {(x - F/2)}
typedef int32_t fixed_t;


fixed_t
add_fp(fixed_t x, fixed_t y) 
{
    return x + y;
}

fixed_t
subtract_fp(fixed_t x, fixed_t y)
{
    return x - y;
}

fixed_t
add_fp_int(fixed_t x, int n)
{
    return (fixed_t) x + INT_TO_FIXED(n);
}

fixed_t
subtract_fp_int(fixed_t x, int n)
{
    return (fixed_t) x - INT_TO_FIXED(n);
}

fixed_t
product_fp_int(fixed_t x, int n)
{
    return (fixed_t) x * n;
}

fixed_t
quotient_fp_int(fixed_t x, int n)
{
    return (fixed_t) x / n;
}

fixed_t
product_fp(fixed_t x, fixed_t y)
{
    return (fixed_t) (((int64_t) x) * y)/ F;
}

fixed_t
quotient_fp(fixed_t x, fixed_t y)
{
    return (fixed_t) (((int64_t) x) * F)/ y;
}



