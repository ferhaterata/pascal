#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_BRANCHES 8

// Round constants
static const uint32_t RCON[MAX_BRANCHES] = {      \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, \
  0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D  \
};

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

// 4-round ARX-box of sparkle ref. implementation
#define ARXBOX(x, y, c)                     \
  (x) += ROT((y), 31), (y) ^= ROT((x), 24), \
  (x) ^= (c),                               \
  (x) += ROT((y), 17), (y) ^= ROT((x), 17), \
  (x) ^= (c),                               \
  (x) += (y),          (y) ^= ROT((x), 31), \
  (x) ^= (c),                               \
  (x) += ROT((y), 24), (y) ^= ROT((x), 16), \
  (x) ^= (c)

// void A(uint32_t x, uint32_t y, int ns) {
void A(uint32_t* x, uint32_t* y) {
    ARXBOX(*x, *y, RCON[0]);
}

