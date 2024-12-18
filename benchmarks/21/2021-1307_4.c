#include <stdint.h>
#define KYBER_POLYBYTES 384
#define KYBER_N 256
#define KYBER_INDCPA_MSGBYTES 32
#define KYBER_Q 3329

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
  int16_t coeffs[KYBER_N];
} poly;

/*************************************************
 * Name:        poly_frommsg
 * Message Encoding Using Polynomial Randomization
 * 
 * Description: Convert 32-byte message to polynomial
 *
 * Arguments:   - poly *r:            pointer to output polynomial
 *              - const uint8_t *msg: pointer to input message
 **************************************************/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]) {
  unsigned int i, j;
  // int16_t mask;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N / 8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  poly r_d;
  poly *p_r[256 + 1];
  uint32_t xorMasks[3] = {0xaaaaaaaa, 0x55555555, 0xaaaaaaaa};
  for (i = 0; i < 256; i += 2) {
    p_r[i] = r;
    p_r[i + 1] = &r_d;
  }
  for (i = 0; i < KYBER_N; i++) {
    r->coeffs[i] = (KYBER_Q + 1) / 2;
    r_d.coeffs[i] = (KYBER_Q + 1) / 2;
  }
  uint32_t b_inv = ((0xaaaa00aa ^ msg[0]) >> 7) & 0xff;
  for (i = 0; i < 255; i++) {
    *(p_r + i) = *(p_r + i + b_inv);
  }
  for (i = 0; i < 2; i++) {
    *(xorMasks + i) = *(xorMasks + i + b_inv);
  }
  for (i = 0; i < KYBER_N / 8; i++) {
    for (j = 0; j < 8; j++) {
      p_r[((xorMasks[j & 1] ^ msg[i]) >> j) & 0xff]->coeffs[8 * i + j] = 0;
    }
  }
}