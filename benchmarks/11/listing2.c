#include <stdint.h>

void test(uint32_t max_length, uint32_t secret_length) {
  uint32_t i;
  uint32_t mask = 0xffffffff;
  uint32_t determiner1;
  for (i = 0; i < max_length; i++) {
    // mask is generated based on data types
    determiner1 = ((i - secret_length) & mask) >> 31;
  }
}