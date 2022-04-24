#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha_helpers.h"

void print_progress_bar (uint64_t progress, uint64_t bar_size, uint64_t min, uint64_t max){
    if (min == max){
        return;
    }
    uint32_t bar_pos = (uint32_t) (((uint64_t) bar_size * (progress - min)) / (max - min));
    float percent = 100.0 * ((float) (progress - min) / (float)(max - min));

    fputs("\r[", stdout);
    for (unsigned int i = 0; i < bar_size; i++){
        if (i < bar_pos){
            fputc('=', stdout);
        } else {
            fputc('-', stdout);
        }
    }
    if (progress > (max - 1500)){
        percent = 100.0;
    }
    printf("] %.3f %%", percent);
    fflush(stdout);
}

uint32_t ceil_divide (uint32_t num, uint32_t denum){
    if (num % denum){
        return 1 + (num / denum);
    } else {
        return num / denum;
    }
}

uint32_t majority (uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t choice (uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ ((~x) & z);
}