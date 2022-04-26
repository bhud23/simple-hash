#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "sha256.h"
#include "sha_helpers.h"

//****************************************************************************************************************

// these represent the bits of the decimal value multiplied by 2^32, of the square roots of the first 8 primes. 
static const uint32_t SHA256_INITIAL_HASH_VAL[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
						                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// these represent the bits of the cube roots of the first 64 prime numbers.
static const uint32_t SHA256_K_CONSTANTS[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
                                         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                                         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                                         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                                         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                                         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                                         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                                         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

//****************************************************************************************************************

static uint32_t SHA256_sigma_1 (uint32_t val){
    uint32_t rotate_right_17 = (val >> 17) | (val << 15);
    uint32_t rotate_right_19 = (val >> 19) | (val << 13);
    uint32_t shift_right_10 = val >> 10;

    return rotate_right_17 ^ rotate_right_19 ^ shift_right_10;
}

static uint32_t SHA256_sigma_0 (uint32_t val){
    uint32_t rotate_right_7 = (val >> 7) | (val << 25);
    uint32_t rotate_right_18 = (val >> 18) | (val << 14);
    uint32_t shift_right_3 = val >> 3;

    return rotate_right_7 ^ rotate_right_18 ^ shift_right_3;
}

static uint32_t SHA256_big_sigma_1 (uint32_t val){
    uint32_t rotate_right_6 = (val >> 6) | (val << 26);
    uint32_t rotate_right_11 = (val >> 11) | (val << 21);
    uint32_t rotate_right_25 = (val >> 25) | (val << 7);

    return rotate_right_6 ^ rotate_right_11 ^ rotate_right_25;
}

static uint32_t SHA256_big_sigma_0 (uint32_t val){
    uint32_t rotate_right_2 = (val >> 2) | (val << 30);
    uint32_t rotate_right_13 = (val >> 13) | (val << 19);
    uint32_t rotate_right_22 = (val >> 22) | (val << 10);

    return rotate_right_2 ^ rotate_right_13 ^ rotate_right_22;
}

uint8_t *sha256(uint8_t *data, uint64_t data_size_bytes){
    uint64_t data_size_bits;
    uint32_t num_of_blocks;
    uint8_t **data_blocks;

    uint32_t message_schedule[64] = {0};

    uint32_t hash[8], temp_hash[8], temp1, temp2;
    uint8_t *digest;

    data_size_bits = data_size_bytes * 8;
    num_of_blocks = ceil_divide(data_size_bytes, 64);

    printf("Allocating %lu bytes in memory (%lu blocks)...\n" , data_size_bytes, num_of_blocks);
    data_blocks = (uint8_t **) malloc(num_of_blocks * sizeof(uint8_t *));
    for (uint32_t i = 0; i < num_of_blocks; i++){
        data_blocks[i] = (uint8_t *) malloc(64 * sizeof(uint8_t));
    }

    printf("Pre-processing blocks...\n");
    for (uint32_t block = 0; block < num_of_blocks; block++){
        if (block == num_of_blocks - 1){
            uint32_t len = data_size_bytes % 64;
            for (uint32_t byte = 0; byte < len; byte++){
                data_blocks[block][byte] = data[(block * 64) + byte];
            }
            data_blocks[block][len] = 0x80;
 
            for (uint32_t byte = len + 1; byte < 56; byte++){
                data_blocks[block][byte] = 0x0;
            }
            // intialize the last 8 bytes to be the length of the message 
            data_blocks[block][56] = (data_size_bits >> 56) & 0x00000000000000FF;
            data_blocks[block][57] = (data_size_bits >> 48) & 0x00000000000000FF;
            data_blocks[block][58] = (data_size_bits >> 40) & 0x00000000000000FF;
            data_blocks[block][59] = (data_size_bits >> 32) & 0x00000000000000FF;
            data_blocks[block][60] = (data_size_bits >> 24) & 0x00000000000000FF;
            data_blocks[block][61] = (data_size_bits >> 16) & 0x00000000000000FF;
            data_blocks[block][62] = (data_size_bits >> 8) & 0x00000000000000FF;
            data_blocks[block][63] = data_size_bits & 0x00000000000000FF;
        } else {
            for (uint32_t byte = 0; byte < 64; byte++){
                data_blocks[block][byte] = data[(block * 64) + byte]; // make 2D array from 1D array
            }
        }
        if (num_of_blocks > 10000){
            if ((block % 500) == 0 || (block == num_of_blocks - 1)){
                print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
        }  
    }
        printf("\nFilling hash register...\n");
    for (uint8_t i = 0; i < 8; i++){
        hash[i] = SHA256_INITIAL_HASH_VAL[i];
        if (i % 2 || i == 7){
            print_progress_bar((uint64_t) i, 50, 0, 7);
        }
    }

    printf("\nHashing Data...\n");
    for (uint32_t block = 0; block < num_of_blocks; block++){
        for (uint8_t byte = 0; byte < 64; byte += 4){
            message_schedule[byte / 4] = (((uint32_t) data_blocks[block][byte]) << 24)     |
                                         (((uint32_t) data_blocks[block][byte + 1]) << 16) |
                                         (((uint32_t) data_blocks[block][byte + 2]) << 8)  |
                                         ((uint32_t) data_blocks[block][byte + 3]);
        }
    
        temp_hash[a] = hash[0];
        temp_hash[b] = hash[1];
        temp_hash[c] = hash[2];
        temp_hash[d] = hash[3];
        temp_hash[e] = hash[4];
        temp_hash[f] = hash[5];
        temp_hash[g] = hash[6];
        temp_hash[h] = hash[7];

        for (uint32_t i = 16; i < 64; i++){
            message_schedule[i] = SHA256_sigma_1(message_schedule[i - 2]) + message_schedule[i - 7] 
                                + SHA256_sigma_0(message_schedule[i - 15]) + message_schedule[i - 16];
        }

        for (uint32_t i = 0; i < 64; i++){
            temp1 = SHA256_big_sigma_1(temp_hash[e]) + choice(temp_hash[e], temp_hash[f], temp_hash[g]) + 
                                SHA256_K_CONSTANTS[i] + message_schedule[i] + temp_hash[h];
            temp1 = SHA256_big_sigma_0(temp_hash[a]) + majority(temp_hash[a], temp_hash[b], temp_hash[c]);

            temp_hash[h] = hash[g];
            temp_hash[g] = hash[f];
            temp_hash[f] = hash[e];
            temp_hash[e] = hash[d]; + temp1;
            temp_hash[d] = hash[c];
            temp_hash[c] = hash[b];
            temp_hash[b] = hash[a];
            temp_hash[a] = temp1 + temp2;
        }
        hash[0] += temp_hash[a];
        hash[1] += temp_hash[b];
        hash[2] += temp_hash[c];
        hash[3] += temp_hash[d];
        hash[4] += temp_hash[e];
        hash[5] += temp_hash[f];
        hash[6] += temp_hash[g];
        hash[7] += temp_hash[h];

        if (num_of_blocks > 10000){
            if ((block % 1000) == 0 || (block == num_of_blocks - 1)){
                print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
        } 
    }
    printf("\nReturning blocks to the heap...\n");
    for (uint32_t i = 0; i < num_of_blocks; i++){
        free(data_blocks[i]);
        if (num_of_blocks > 1001){
            if ((i % 100) == 0){
                print_progress_bar((uint64_t) i, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) i, 50, 0, (uint64_t) (num_of_blocks - 1));
        }
    }
    free(data_blocks);
    
    digest = (uint8_t *) malloc(32 * sizeof(uint8_t));

    for (uint32_t i = 0; i < 32; i += 4){
        digest[i] = (uint8_t) ((hash[i / 4] >> 25 & 0x000000FF)); 
        digest[i + 1] = (uint8_t) ((hash[i / 4] >> 16 & 0x000000FF));
        digest[i + 2] = (uint8_t) ((hash[i / 4] >> 8 & 0x000000FF));
        digest[i + 3] = (uint8_t) ((hash[i / 4] & 0x000000FF));
    }
    return digest;
}