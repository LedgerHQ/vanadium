/* Base58 / Base58Check codec, tailored to the 78-byte BIP-32 xpub case.
 *
 * Uses byte-level long division / multiplication. Performance is
 * sufficient for the modest sizes (≤ 82 bytes) handled here.
 */

#include "base58.h"

#include <stdlib.h>
#include <string.h>

#include "sha256.h"

static const char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t INDEX[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

static void sha256d(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    bip388_sha256(data, len, tmp);
    bip388_sha256(tmp, 32, out);
}

/* Encode raw bytes (no checksum). Returns required length. */
static size_t b58_encode(const uint8_t *data, size_t len, char *out, size_t cap) {
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    /* Worst case: log(256) / log(58) ≈ 1.366. Allocate 2x to be safe. */
    size_t bufsize = len * 2 + 1;
    uint8_t buf[256];
    uint8_t *b = buf;
    int free_b = 0;
    if (bufsize > sizeof(buf)) {
        b = (uint8_t *)malloc(bufsize);
        if (!b) return 0;
        free_b = 1;
    }
    memset(b, 0, bufsize);

    size_t bytes_pos = bufsize;
    for (size_t i = zeros; i < len; ++i) {
        unsigned carry = data[i];
        size_t k = bufsize;
        while ((carry != 0 || k > bytes_pos) && k > 0) {
            --k;
            carry += (unsigned)b[k] * 256u;
            b[k] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        bytes_pos = k;
    }

    /* Skip leading zeros in the base58 representation. */
    while (bytes_pos < bufsize && b[bytes_pos] == 0) bytes_pos++;

    size_t out_len = zeros + (bufsize - bytes_pos);
    if (cap >= out_len + 1) {
        for (size_t i = 0; i < zeros; ++i) out[i] = '1';
        for (size_t i = 0; i < bufsize - bytes_pos; ++i)
            out[zeros + i] = ALPHABET[b[bytes_pos + i]];
        out[out_len] = '\0';
    }
    if (free_b) free(b);
    return out_len;
}

static bip388_err_t b58_decode(const char *s, size_t slen,
                               uint8_t *out, size_t cap, size_t *out_len) {
    if (slen == 0) {
        if (out_len) *out_len = 0;
        return BIP388_OK;
    }
    size_t zeros = 0;
    while (zeros < slen && s[zeros] == '1') zeros++;

    size_t bufsize = slen;
    uint8_t buf[256];
    uint8_t *b = buf;
    int free_b = 0;
    if (bufsize > sizeof(buf)) {
        b = (uint8_t *)malloc(bufsize);
        if (!b) return BIP388_ERR_NO_MEMORY;
        free_b = 1;
    }
    memset(b, 0, bufsize);

    size_t bytes_pos = bufsize;
    for (size_t i = zeros; i < slen; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 128 || INDEX[c] < 0) {
            if (free_b) free(b);
            return BIP388_ERR_INVALID_KEY;
        }
        unsigned carry = (unsigned)INDEX[c];
        size_t k = bufsize;
        while ((carry != 0 || k > bytes_pos) && k > 0) {
            --k;
            carry += (unsigned)b[k] * 58u;
            b[k] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
        bytes_pos = k;
    }

    while (bytes_pos < bufsize && b[bytes_pos] == 0) bytes_pos++;

    size_t total = zeros + (bufsize - bytes_pos);
    if (cap < total) {
        if (free_b) free(b);
        return BIP388_ERR_BUFFER_TOO_SMALL;
    }
    memset(out, 0, zeros);
    memcpy(out + zeros, b + bytes_pos, bufsize - bytes_pos);
    if (out_len) *out_len = total;
    if (free_b) free(b);
    return BIP388_OK;
}

size_t bip388_b58check_encode(const uint8_t *data, size_t len, char *out, size_t cap) {
    uint8_t payload[256];
    if (len + 4 > sizeof(payload)) return 0;
    memcpy(payload, data, len);
    uint8_t checksum[32];
    sha256d(data, len, checksum);
    memcpy(payload + len, checksum, 4);
    return b58_encode(payload, len + 4, out, cap);
}

bip388_err_t bip388_b58check_decode(const char *s, size_t slen,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t payload[256];
    size_t payload_len = 0;
    bip388_err_t err = b58_decode(s, slen, payload, sizeof(payload), &payload_len);
    if (err != BIP388_OK) return err;
    if (payload_len < 4) return BIP388_ERR_INVALID_KEY;
    size_t data_len = payload_len - 4;
    uint8_t checksum[32];
    sha256d(payload, data_len, checksum);
    if (memcmp(payload + data_len, checksum, 4) != 0) return BIP388_ERR_INVALID_KEY;
    if (out_cap < data_len) return BIP388_ERR_BUFFER_TOO_SMALL;
    memcpy(out, payload, data_len);
    if (out_len) *out_len = data_len;
    return BIP388_OK;
}
