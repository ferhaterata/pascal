#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D 636
#define PARAMS_Q_BITS 12
#define PARAMS_P_BITS 9
#define PARAMS_T_BITS 6
#define PARAMS_B_BITS 2
#define PARAMS_F 0
#define PARAMS_Z_BITS   (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS)
#define PARAMS_H3                               \
  ((1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + \
   (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - \
   (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1)))
#define PARAMS_XE 0
#define PARAMS_KAPPA (8 * PARAMS_KAPPA_BYTES)
#define CEIL_DIV(a,b) ((a+b-1)/b)
#define BITS_TO_BYTES(b) (CEIL_DIV(b,8))
#define PARAMS_MU CEIL_DIV((PARAMS_KAPPA + PARAMS_XE), PARAMS_B_BITS)

typedef uint8_t modp_t;

void r5_cpa_pke_decrypt(uint8_t *m, const uint8_t *sk, const uint8_t *ct) {
  size_t i;
  modp_t X_prime[PARAMS_MU];
  uint8_t m1[BITS_TO_BYTES(PARAMS_MU * PARAMS_B_BITS)];
  modp_t v[PARAMS_MU];
  //...

  // X' = v - X', compressed to 1 bit
  modp_t x_p;
  memset(m1, 0, sizeof(m1));
  for (i = 0; i < PARAMS_MU; i++) {
    // v - X' as mod q value (to be able to perform the rounding!)
    x_p = (modp_t)((v[i] << (PARAMS_P_BITS - PARAMS_T_BITS)) - X_prime[i]);
    x_p = (modp_t)(((x_p + PARAMS_H3) >> (PARAMS_P_BITS - PARAMS_B_BITS)) &
                   ((1 << PARAMS_B_BITS) - 1));
    m1[i * PARAMS_B_BITS >> 3] = (uint8_t)(m1[i * PARAMS_B_BITS >> 3] |
                                           (x_p << ((i * PARAMS_B_BITS) & 7)));
  }
}
