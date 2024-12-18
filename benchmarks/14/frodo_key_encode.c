#include <stdint.h>

#define PARAMS_N 640
#define PARAMS_NBAR 8
#define PARAMS_EXTRACTED_BITS 2
#define PARAMS_LOGQ 15

void frodo_key_encode(uint16_t *out, const uint16_t *in) {  // Encoding
  unsigned int i, j, npieces_word = 8;
  unsigned int nwords = (PARAMS_NBAR * PARAMS_NBAR) / 8;
  uint64_t temp, mask = ((uint64_t)1 << PARAMS_EXTRACTED_BITS) - 1;
  uint16_t *pos = out;

  for (i = 0; i < nwords; i++) {
    temp = 0;
    for (j = 0; j < PARAMS_EXTRACTED_BITS; j++)
      temp |= ((uint64_t)((uint8_t *)in)[i * PARAMS_EXTRACTED_BITS + j])
              << (8 * j);
    for (j = 0; j < npieces_word; j++) {
      *pos = (uint16_t)((temp & mask) << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS));
      temp >>= PARAMS_EXTRACTED_BITS;
      pos++;
    }
  }
}