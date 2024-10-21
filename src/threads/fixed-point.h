#pragma once
#include <stdint.h>
#define FRACTION 14
#define F (1 << FRACTION)
#define INT_TO_FIXED(n) n * F
#define ROUND_TO_ZERO(x) x / F
#define ROUND_TO_NEAREST(x) (((x) >= 0) ? ((x) + (F / 2)) : ((x) - (F / 2)))

typedef int32_t fixed_t;

fixed_t add_fp(fixed_t x, fixed_t y);
fixed_t subtract_fp(fixed_t x, fixed_t y);
fixed_t add_fp_int(fixed_t x, int n);
fixed_t subtract_fp_int(fixed_t x, int n);
fixed_t product_fp_int(fixed_t x, int n);
fixed_t quotient_fp_int(fixed_t x, int n);
fixed_t product_fp(fixed_t x, fixed_t y);
fixed_t quotient_fp(fixed_t x, fixed_t y);