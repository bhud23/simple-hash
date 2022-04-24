#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>

#include "sha256.h"
#include "sha512.h"

int main (int argc, char *argv[]){
    FILE *file;
    uint64_t *digest;
    uint8_t *data;
    uint64_t file_size_bytes = 0;
    struct stat file_status;

    printf("%d file(s) arguments\n", argc - 1);
    if (argc != 2){
        printf("Error: incorrect amount of arguments. Please provide one (1) argument.\n");
        printf("Use: %s <path_to_file\n>", argv[0]);
        exit(EXIT_FAILURE);
    }
    if ((file = fopen(argv[1], "rb")) == NULL){
        printf("Error: could not open %s\n", argv[1]);
        exit(EXIT_FAILURE);
    }

    printf("Hashing %s\n", argv[1]);
    stat(argv[1], &file_status);
    file_size_bytes = file_status.st_size;
    data = (uint8_t *) malloc(file_size_bytes * sizeof(uint8_t));
    fread(data, sizeof(uint8_t), file_size_bytes, file);
    fclose(file);

    digest = sha512(data, file_size_bytes);
    printf("\nDigest: ");
    for (uint32_t i = 0; i < 32; i++){
        printf("%02x ", digest[i]);
    }
    printf("\n");
    free(digest);

    return EXIT_SUCCESS;
}