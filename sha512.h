#ifndef SHA512_H
#define SHA512_H
#include <stdint.h>
#include "sha512.c"

uint64_t *sha512(uint8_t *data, uint64_t data_size_bytes); 

#endif