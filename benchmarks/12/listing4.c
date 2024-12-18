#include <stdint.h>

void test(uint32_t i, uint32_t j) {
  uint32_t a, b, v, x;
  uint32_t mask = 0xffffffff;
  uint32_t determiner2;
  uint32_t determiner3;
  // mask is generated based on data types
  determiner2 = !(((i - 1) & mask) >> 31);
  a = b * determiner2;
  determiner3 = -((uint32_t)- j >> 31);
  v = x & determiner3 + v & !determiner3;
}