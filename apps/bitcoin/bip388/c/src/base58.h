#ifndef BIP388_BASE58_H
#define BIP388_BASE58_H

#include <stddef.h>
#include <stdint.h>

#include "../include/bip388.h"

/* Decode a base58check-encoded NUL-terminated string into a fixed-size
 * buffer. On success, writes the decoded payload (excluding checksum) and
 * returns BIP388_OK. */
bip388_err_t bip388_b58check_decode(const char *s, size_t len,
                                    uint8_t *out, size_t out_cap, size_t *out_len);
/* Returns the required string length (excluding NUL). */
size_t bip388_b58check_encode(const uint8_t *data, size_t len,
                              char *out, size_t cap);

#endif
