#include <stdint.h>
#define offset 31

/*************************************************
 * Name:        hw
 * Description: Compute the Hamming weight of a byte
 * Arguments:   - unsigned char a: input byte
 **************************************************/
unsigned set_bit(uint32_t a) {
  unsigned char i, r = 0;
  for (i = 0; i < 32; i++) r += (a >> i) & 1;
  return r > 0;
}

void test() {
  uint32_t i, xorVal, index, anyOnes, out;
  uint32_t mask = 0xffffffff;
  uint32_t determiner4;
  uint32_t length = 32;
  uint32_t b[length];
  for (i = 0; i < length; i++) {
    // mask is generated based on data types
    xorVal = i ^ index;
    // anyOnes = 0 if i = index , 1 otherwise
    anyOnes = set_bit(xorVal);
    determiner4 = (anyOnes & 1) - 1;
    out = b[i] & determiner4;
  }
}
