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


/* Unsigned comparisons */
/* Return 1 if condition is true, 0 otherwise */
int ct_lt_u32(uint32_t x, uint32_t y)
{
    return (x^((x^y)|((x-y)^y)))>>31;
}