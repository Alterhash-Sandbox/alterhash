#ifndef CSIPHASH_SIPHASH_ORG_H
#define CSIPHASH_SIPHASH_ORG_H

#include <inttypes.h>

uint64_t siphash_org(uint8_t key[16], char data[], int len, int c, int d);

#endif
