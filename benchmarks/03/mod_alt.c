#include <stdint.h>

// Listing 3: Alternative mod3() implementation
uint16_t mod3_alt(uint16_t a) {
  uint16_t r;

  r = (a >> 8) + (a & 0xff);
  r = (r >> 4) + (r & 0xf);
  r = (r >> 2) + (r & 0x3);
  r = (r >> 2) + (r & 0x3);
  r = ((r >> 2) + (r)) & 0x3;         // Map 4 −> 1
  return (r + ((r + 1) >> 2)) & 0x3;  // Map 3 −> 0
}