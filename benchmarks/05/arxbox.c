#include <stdint.h>

// Rotate left for 16 bit registers.
#define ROTL(x, n) (((x) << n) | ((x) >> (16 - (n))))

void A(uint16_t* l, uint16_t* r) {
  (*l) = ROTL((*l), 9);
  (*l) += (*r);
  (*r) = ROTL((*r), 2);
  (*r) ^= (*l);
}
