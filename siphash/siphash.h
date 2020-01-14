#ifndef CSIPHASH_SIPHASH_H
#define CSIPHASH_SIPHASH_H

#include <inttypes.h>

uint64_t siphash(uint64_t k0, uint64_t k1, char * data, uint32_t len, int c, int d);
#endif
