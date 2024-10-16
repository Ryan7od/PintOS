#include <stdint.h>;
#define FRACTION 14
#define F 1 << FRACTION
#define INT_TO_FIXED(n) n * F
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



