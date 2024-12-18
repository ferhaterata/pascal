#include <stdint.h>

#define NTRU_LOGQ 11
#define NTRU_N 509
#define NTRU_Q (1 << NTRU_LOGQ)

typedef struct {
  uint16_t coeffs[NTRU_N];
} poly;

/* Map {0, 1, 2} -> {0, 1, q-1} in place */
// Listing 2: poly_Z3_to_Zq() implementation
void poly_Z3_to_Zq(poly *r) {
  int i;
  for (i = 0; i < NTRU_N; i++)
    r->coeffs[i] = r->coeffs[i] | ((-(r->coeffs[i] >> 1)) & (NTRU_Q - 1));
}