#include <stdint.h>

#define NEWHOPE_N 512
#define NEWHOPE_Q 12289

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
  uint16_t coeffs[NEWHOPE_N];
} poly __attribute__((aligned(32)));

/*************************************************
 * Name:        poly_frommsg
 * Description: Convert 32-byte message to polynomial
 * Arguments:   - poly *r:                  pointer to output polynomial
 *              - const unsigned char *msg: pointer to input message
 **************************************************/
void poly_frommsg(poly *r, const unsigned char *msg) {
  unsigned int i, j, tmp;
  for (i = 0; i < 32; i++)  // XXX: MACRO for 32
  {
    for (j = 0; j < 8; j++) {
      tmp = (NEWHOPE_Q / 2) * ((msg[i] >> j) & 1);
      r->coeffs[8 * i + j + 0] = tmp;
      r->coeffs[8 * i + j + 256] = tmp;
      //   mask = -((msg[i] >> j) & 1);
      //   r->coeffs[8 * i + j + 0] = mask & (NEWHOPE_Q / 2);
      // r->coeffs[8 * i + j + 256] = mask & (NEWHOPE_Q / 2);
      
    }
  }
}