#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include "sha256.c"

uint8_t *sha256(uint8_t *data, uint64_t data_size_bytes);

#endif