#include <stdio.h>
#include <string.h>
#include "siphash.h"

#define ROTATE_LEFT(x, b) (unsigned long)(((x) << (b)) | ((x) >> (64 - (b))))

#define COMPRESS                \
  v0 += v1;                     \
  v2 += v3;                     \
  v1 = ROTATE_LEFT(v1, 13);     \
  v3 = ROTATE_LEFT(v3, 16);     \
  v1 ^= v0;                     \
  v3 ^= v2;                     \
  v0 = ROTATE_LEFT(v0, 32);     \
  v2 += v1;                     \
  v0 += v3;                     \
  v1 = ROTATE_LEFT(v1, 17);     \
  v3 = ROTATE_LEFT(v3, 21);     \
  v1 ^= v2;                     \
  v3 ^= v0;                     \
  v2 = ROTATE_LEFT(v2, 32);

#define DIGEST_BLOCK            \
  v3 ^= m;                      \
  do {                          \
    int i;                      \
    for(i = 0; i < c; i++){     \
      COMPRESS                  \
    }                           \
  } while (0);                  \
  v0 ^= m;

#define U8TO64_LE(p)                                                           \
  (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                          \
   ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                   \
   ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                   \
   ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

uint64_t siphash(uint64_t k0, uint64_t k1, char * data, uint32_t len, int c, int d){
    //uint64_t k0 = U8TO64_LE(key);
    //uint64_t k1 = U8TO64_LE(key + 8);

    uint64_t v0 = 0x736f6d6570736575 ^ k0;
    uint64_t v1 = 0x646f72616e646f6d ^ k1;
    uint64_t v2 = 0x6c7967656e657261 ^ k0;
    uint64_t v3 = 0x7465646279746573 ^ k1;

    uint64_t volatile m = 0;

    int volatile i, iter = 0, index = 0;

    for (; index < len; index++) {
        m |= ((uint64_t) data[index]) << (iter++ * 8);
        if (iter >= 8) {
            DIGEST_BLOCK
            iter = 0;
            m = 0;
        }
    }

    while (iter < 7) {
        m |= 0 << (iter++ * 8);
    }

    m |= ((uint64_t) len) << (iter * 8);

    DIGEST_BLOCK

    v2 ^= 0xff;

    for(i = 0; i < d; i++){
        COMPRESS
    }

    uint64_t volatile res =(uint64_t)(v0 ^ v1 ^ v2 ^ v3);
    return ((uint64_t)(v0 ^ v1 ^ v2 ^ v3));
}
