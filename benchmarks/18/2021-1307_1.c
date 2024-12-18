#include <stdint.h>
#define KYBER_POLYBYTES		384
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
* Name:        poly_frommsg: 
* Message Encoding With Multiplication
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  unsigned int i,j;
  int16_t mask;

#if (KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif

  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      mask = ((msg[i] >> j) & 1);
      r->coeffs[8*i+j] = mask * ((KYBER_Q+1)/2);
    }
  }
}