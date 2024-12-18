#include <stdint.h>

// Listing 1: mod3() implementation
uint16_t mod3(uint16_t a) {
  uint16_t r;
  int16_t t, c;

  r = (a >> 8) + (a & 0xff);
  r = (r >> 4) + (r & 0xf);
  r = (r >> 2) + (r & 0x3);
  r = (r >> 2) + (r & 0x3);

  t = r - 3;
  c = t >> 15;
  return (c & r) ^ (~c & t);
}