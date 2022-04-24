#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha512.h"
#include "sha_helpers.h"

static const uint64_t SHA512_INITIAL_HASH_VAL[8] = {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};

static const uint64_t SHA512_K_CONSTANTS[80] = {0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                                         0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                                         0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                                         0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                                         0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                                         0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                                         0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                                         0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                                         0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                                         0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                                         0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                                         0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                                         0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                                         0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                                         0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                                         0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                                         0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                                         0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                                         0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                                         0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

//****************************************************************************************************************
static uint64_t SHA512_sigma_0 (uint64_t val){
    uint64_t rotate_right_1 = (val >> 1) | (val << 63);
    uint64_t rotate_right_8 = (val >> 8) | (val << 56);
    uint64_t shift_right_7 = val >> 7;

    return rotate_right_1 ^ rotate_right_8 ^ shift_right_7;
}

static uint64_t SHA512_sigma_1 (uint64_t val){
    uint64_t rotate_right_19 = (val >> 19) | (val << 45);
    uint64_t rotate_right_61 = (val >> 61) | (val << 3);
    uint64_t shift_right_6 = val >> 6;

    return rotate_right_19 ^ rotate_right_61 ^ shift_right_6;
}

static uint64_t SHA512_big_sigma_0 (uint64_t val){
    uint64_t rotate_right_28 = (val >> 28) | (val << 36);
    uint64_t rotate_right_34 = (val >> 34) | (val << 30);
    uint64_t rotate_right_39 = (val >> 39) | (val << 25);

    return rotate_right_28 ^ rotate_right_34 ^ rotate_right_39;
}

static uint64_t SHA512_big_sigma_1 (uint64_t val){
    uint64_t rotate_right_14 = (val >> 14) | (val << 50);
    uint64_t rotate_right_18 = (val >> 18) | (val << 46);
    uint64_t rotate_right_41 = (val >> 41) | (val << 23);

    return rotate_right_14 ^ rotate_right_18 ^ rotate_right_41;
}

uint64_t *sha512(uint8_t *data, uint64_t data_size_bytes){ // returns array of 64 8-bit numbers
    uint64_t data_size_bits;
    uint32_t num_of_blocks;
    uint64_t **data_blocks;
 
    uint64_t message_schedule[64];

    uint64_t hash[8], temp_hash[8], temp1, temp2; 
    uint64_t *digest;

    data_size_bits = data_size_bytes * 8;
    num_of_blocks = ceil_divide(data_size_bytes, 1024);

    printf("Allocating %lu bytes in memory (%lu blocks)...\n" , data_size_bytes, num_of_blocks);
    data_blocks = (uint64_t **) malloc(num_of_blocks * sizeof(uint8_t *));
    for (uint32_t i = 0; i < num_of_blocks; i++){
        data_blocks[i] = (uint64_t *) malloc(64 * sizeof(uint64_t));
    }

    printf("Pre-processing blocks...\n");
    for (uint32_t block = 0; block < num_of_blocks; block++){
        if (block == num_of_blocks - 1){ // if in last block 
            uint32_t len = data_size_bytes % 128;
            for (uint32_t byte = 0; byte < len; byte++){
                data_blocks[block][byte] = data[(block * 128) + byte];
            }
            data_blocks[block][len] = 0x80;

            for (uint32_t byte = len + 1; byte < 120; byte++){
                data_blocks[block][byte] = 0x0;
            }

            data_blocks[block][112] = 0x0;
            data_blocks[block][113] = 0x0;
            data_blocks[block][114] = 0x0;
            data_blocks[block][115] = 0x0;
            data_blocks[block][116] = 0x0;
            data_blocks[block][117] = 0x0;
            data_blocks[block][118] = 0x0;
            data_blocks[block][119] = 0x0;
            data_blocks[block][120] = (data_size_bits >> 56) & 0x00000000000000FF;
            data_blocks[block][121] = (data_size_bits >> 48) & 0x00000000000000FF;
            data_blocks[block][122] = (data_size_bits >> 40) & 0x00000000000000FF;
            data_blocks[block][123] = (data_size_bits >> 32) & 0x00000000000000FF;
            data_blocks[block][124] = (data_size_bits >> 24) & 0x00000000000000FF;
            data_blocks[block][125] = (data_size_bits >> 16) & 0x00000000000000FF;
            data_blocks[block][126] = (data_size_bits >> 8) & 0x00000000000000FF;
            data_blocks[block][127] = data_size_bits & 0x00000000000000FF;
        } else {
            for (uint32_t byte = 0; byte < 128; byte++){
                data_blocks[block][byte] = data[(block * 128) + byte];
            }
        }
        if (num_of_blocks > 1000){
            if ((block % 1000) == 0 || (block == num_of_blocks - 1)){
                print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
        }
    }

    printf("\nFilling hash register...\n");
    for (uint8_t i = 0; i < 8; i++){
        hash[i] = SHA512_INITIAL_HASH_VAL[i];
        if (i % 2){
            print_progress_bar((uint64_t) i, 50, 0, (uint64_t) 7);
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
        
        for (uint32_t i = 16; i < 80; i++){
            message_schedule[i] = SHA512_sigma_1(message_schedule[i - 2]) + message_schedule[ i - 7] 
                                + SHA512_sigma_0(message_schedule[i - 15]) + message_schedule[i - 16];
        }
        temp_hash[a] = hash[0];
        temp_hash[b] = hash[1];
        temp_hash[c] = hash[2];
        temp_hash[d] = hash[3];
        temp_hash[e] = hash[4];
        temp_hash[f] = hash[5];
        temp_hash[g] = hash[6];
        temp_hash[h] = hash[7];

        for (uint32_t i = 0; i < 80; i++){
            temp1 = SHA512_big_sigma_1(temp_hash[e]) + choice(temp_hash[e], temp_hash[f], temp_hash[g]) + 
                    SHA512_K_CONSTANTS[i]  + message_schedule[i] + temp_hash[h];
            temp1 = SHA512_big_sigma_0(temp_hash[a]) + majority(temp_hash[a], temp_hash[b], temp_hash[c]);

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

        if (num_of_blocks > 1000){
            if ((block % 10) == 0 || (block == num_of_blocks - 1)){
                print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) block, 50, 0, (uint64_t) (num_of_blocks - 1));
        }
    }
    printf("\nReturning blocks to the heap...\n");
    for (uint32_t i = 0; i < num_of_blocks; i++){
        free(data_blocks[i]);
        if (num_of_blocks > 1000){
            if ((i % 1000) == 0 || (i == num_of_blocks - 1)){
                print_progress_bar((uint64_t) i, 50, 0, (uint64_t) (num_of_blocks - 1));
            }
        } else {
            print_progress_bar((uint64_t) i, 50, 0, (uint64_t) (num_of_blocks - 1));
        }
    }
    free(data_blocks);
    digest = (uint64_t *) malloc(8 * sizeof(uint64_t));

    for (uint32_t i = 0; i < 2; i++){
        digest[i] = (uint64_t) ((hash[i / 4] >> 25 & 0x000000FF));
        digest[i + 1] = (uint64_t) ((hash[i / 4] >> 16 & 0x000000FF));
        digest[i + 2] = (uint64_t) ((hash[i / 4] >> 8 & 0x000000FF));
        digest[i + 3] = (uint64_t) ((hash[i / 4] & 0x000000FF));
    }
    return digest;
}