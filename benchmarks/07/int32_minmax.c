#include <stdint.h>

#define int32_MINMAX(a, b)                              \
  do {                                                  \
    int32_t ab = (b) ^ (a);                             \
    int32_t c = (int32_t)((int64_t)(b) - (int64_t)(a)); \
    c ^= ab & (c ^ (b));                                \
    c >>= 31;                                           \
    c &= ab;                                            \
    (a) ^= c;                                           \
    (b) ^= c;                                           \
  } while (0)

void test(int32_t* a, int32_t* b) { int32_MINMAX(*a, *b); }