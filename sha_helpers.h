#ifndef SHA_HELPERS_H
#define SHA_HELPERS_H
#include <stdint.h>
#include "sha_helpers.c"

enum temp_hash {a, b, c, d, e, f, g, h};

void print_progress_bar (uint64_t progress, uint64_t bar_size, uint64_t min, uint64_t max);

uint32_t ceil_divide (uint32_t num, uint32_t denum);

uint32_t majority (uint32_t x, uint32_t y, uint32_t z);

uint32_t choice (uint32_t x, uint32_t y, uint32_t z);

#endif