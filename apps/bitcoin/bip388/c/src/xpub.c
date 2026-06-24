#include "../include/bip388.h"

#include <string.h>

#include "base58.h"

bip388_err_t bip388_xpub_from_str(const char *s, size_t len, bip388_xpub_t *out) {
    uint8_t buf[128];
    size_t decoded = 0;
    bip388_err_t err = bip388_b58check_decode(s, len, buf, sizeof(buf), &decoded);
    if (err != BIP388_OK) return err;
    if (decoded != 78) return BIP388_ERR_INVALID_KEY;
    memcpy(out->raw, buf, 78);
    return BIP388_OK;
}

size_t bip388_xpub_to_str(const bip388_xpub_t *x, char *out, size_t cap) {
    return bip388_b58check_encode(x->raw, 78, out, cap);
}
