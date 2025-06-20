#include <stddef.h>
#include <stdint.h>
#include "randombytes.h"

/* Forward declaration of our custom implementation from utils.c */
extern void custom_randombytes_impl(uint8_t *out, size_t outlen);

/* This function is the randombytes implementation that calls our custom implementation */
void randombytes(uint8_t *out, size_t outlen) {
    custom_randombytes_impl(out, outlen);
}
