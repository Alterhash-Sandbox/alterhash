#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "siphash_org.h"
#include "siphash.h"

#define U8TO64_LE(p)                                                           \
  (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                          \
   ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                   \
   ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                   \
   ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

int main(){
  // Use current time as seed for random generator
  srand(time(0)); 

  int       n = 1000;
  uint32_t  len;
  char      data[129];
  uint8_t   key[16];
  int       c;
  int       d;
  uint64_t  k0;
  uint64_t  k1;
  uint64_t  sip_org;
  uint64_t  sip;

  for (int i = 0; i < n; i++) {
    k0 = 0;
    k1 = 0;
    len = rand() % 128; // maximum 128

    for (int j = 0; j < len; j++) {
      data[j] = rand();
    }
    data[len] = 0;

    for (int j = 0; j < 16; j++) {
      key[j] = rand();
      if (j < 8)
        k0 = k0 | ((uint64_t)key[j] << (8 * j));
      else
        k1 = k1 | ((uint64_t)key[j] << (8 * (j - 8)));
    }

    c = 1 + rand() % 2;
    if (c == 1)
      d = 2;
    else
      d = 4;

    sip_org = siphash_org(key, data, len, c, d);
    sip     = siphash(k0, k1, data, len, c, d);

    if (sip_org != sip) {
      printf("ERROR!: sip_org == 0x%lx | sip == 0x%lx\n", sip_org, sip);
      return 1;
    }

  }

  printf("Random test is passing!\n");
  return 0;
}
