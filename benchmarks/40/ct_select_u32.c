/* https://godbolt.org/z/fE3j8xzEq */
#include <stdint.h>
#include <limits.h>

/*
Constant-time integer comparisons
 
Written in 2014 by Samuel Neves <sneves@dei.uc.pt>
 
To the extent possible under law, the author(s) have dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.
 
You should have received a copy of the CC0 Public Domain Dedication along with
this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/


/* Generate a mask: 0xFFFFFFFF if bit != 0, 0 otherwise */
static int ct_isnonzero_u32(uint32_t x)
{
    return (x|-x)>>31;
}

static uint32_t ct_mask_u32(uint32_t bit)
{
    return -(uint32_t)ct_isnonzero_u32(bit);
}

/* Conditionally return x or y depending on whether bit is set */
/* Equivalent to: return bit ? x : y */
uint32_t ct_select_u32(uint32_t x, uint32_t y, uint32_t bit)
{
    uint32_t m = ct_mask_u32(bit);
    return (x&m) | (y&~m);
    /* return ((x^y)&m)^y; */
}
