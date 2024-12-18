#include <stdint.h>
#define KYBER_Q 3329

/*************************************************
 * Name:        csubq
 * Description: Conditionallly subtract q
 * Arguments:   - int16_t x: input integer
 * Returns:     a - q if a >= q, else a
 **************************************************/
int16_t csubq(int16_t a) {
  a -= KYBER_Q;
  a += (a >> 15) & KYBER_Q;
  return a;
}