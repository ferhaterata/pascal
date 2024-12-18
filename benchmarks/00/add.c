#include <stdint.h>
#define KYBER_Q 102 

int16_t add(int16_t a) {
  a = a + KYBER_Q;
  return a;
}