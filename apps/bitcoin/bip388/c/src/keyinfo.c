/* KeyOrigin / KeyInformation parsing, formatting, free. */

#include "../include/bip388.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

void bip388_key_origin_free(bip388_key_origin_t *o) {
    if (!o) return;
    free(o->path);
    o->path = NULL;
    o->n_path = 0;
}

void bip388_key_info_free(bip388_key_info_t *ki) {
    if (!ki) return;
    if (ki->has_origin) bip388_key_origin_free(&ki->origin);
}

/* Parse a derivation-step token, e.g. "0", "5", "1'". */
static bip388_err_t parse_step(const char *s, size_t len, uint32_t *out) {
    if (len == 0) return BIP388_ERR_INVALID_KEY;
    bool hardened = false;
    if (s[len - 1] == '\'') {
        hardened = true;
        len--;
        if (len == 0) return BIP388_ERR_INVALID_KEY;
    }
    /* Reject leading zeros for multi-digit numbers. */
    if (s[0] == '0' && len > 1) return BIP388_ERR_NUMBER_OUT_OF_RANGE;
    uint64_t v = 0;
    for (size_t i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)s[i])) return BIP388_ERR_INVALID_KEY;
        v = v * 10 + (uint64_t)(s[i] - '0');
        if (v >= BIP388_HARDENED_INDEX) return BIP388_ERR_INVALID_KEY;
    }
    *out = (uint32_t)v + (hardened ? BIP388_HARDENED_INDEX : 0);
    return BIP388_OK;
}

bip388_err_t bip388_key_origin_parse(const char *s, size_t len, bip388_key_origin_t *out) {
    if (len == 0) return BIP388_ERR_EMPTY_INPUT;
    /* fingerprint is exactly 8 hex chars before the first '/' or end. */
    size_t first_slash = 0;
    while (first_slash < len && s[first_slash] != '/') first_slash++;
    if (first_slash != 8) return BIP388_ERR_INVALID_LENGTH;
    uint32_t fp = 0;
    for (size_t i = 0; i < 8; ++i) {
        char c = s[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = 10 + c - 'a';
        else if (c >= 'A' && c <= 'F') d = 10 + c - 'A';
        else return BIP388_ERR_INVALID_KEY;
        fp = (fp << 4) | (uint32_t)d;
    }
    /* Count remaining steps. */
    size_t n_steps = 0;
    for (size_t i = first_slash; i < len; ++i) {
        if (s[i] == '/') n_steps++;
    }
    uint32_t *path = NULL;
    if (n_steps > 0) {
        path = (uint32_t *)malloc(n_steps * sizeof(uint32_t));
        if (!path) return BIP388_ERR_NO_MEMORY;
    }
    size_t idx = 0;
    size_t i = first_slash;
    while (i < len) {
        if (s[i] != '/') { free(path); return BIP388_ERR_INVALID_SYNTAX; }
        i++;
        size_t start = i;
        while (i < len && s[i] != '/') i++;
        uint32_t v;
        bip388_err_t err = parse_step(s + start, i - start, &v);
        if (err) { free(path); return err; }
        path[idx++] = v;
    }
    out->fingerprint = fp;
    out->path = path;
    out->n_path = n_steps;
    return BIP388_OK;
}

size_t bip388_key_origin_format(const bip388_key_origin_t *o, char *out, size_t cap) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    bip388_sbuf_pushf(&b, "%08x", o->fingerprint);
    for (size_t i = 0; i < o->n_path; ++i) {
        uint32_t s = o->path[i];
        if (s >= BIP388_HARDENED_INDEX)
            bip388_sbuf_pushf(&b, "/%u'", s - BIP388_HARDENED_INDEX);
        else
            bip388_sbuf_pushf(&b, "/%u", s);
    }
    size_t needed = b.len;
    if (cap >= needed + 1) {
        memcpy(out, b.data, needed);
        out[needed] = '\0';
    }
    bip388_sbuf_free(&b);
    return needed;
}

bip388_err_t bip388_key_info_parse(const char *s, bip388_key_info_t *out) {
    if (!s || !*s) return BIP388_ERR_EMPTY_INPUT;
    size_t slen = strlen(s);
    out->has_origin = false;
    out->origin.path = NULL;
    out->origin.n_path = 0;
    size_t pubkey_pos = 0;
    if (s[0] == '[') {
        const char *end = strchr(s, ']');
        if (!end) return BIP388_ERR_INVALID_KEY;
        size_t origin_len = (size_t)(end - s - 1);
        bip388_err_t err = bip388_key_origin_parse(s + 1, origin_len, &out->origin);
        if (err) return err;
        out->has_origin = true;
        pubkey_pos = (size_t)(end - s + 1);
    }
    bip388_err_t err = bip388_xpub_from_str(s + pubkey_pos, slen - pubkey_pos, &out->xpub);
    if (err) {
        if (out->has_origin) bip388_key_origin_free(&out->origin);
        return BIP388_ERR_INVALID_KEY;
    }
    return BIP388_OK;
}

size_t bip388_key_info_format(const bip388_key_info_t *ki, char *out, size_t cap) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    if (ki->has_origin) {
        bip388_sbuf_pushc(&b, '[');
        char obuf[256];
        size_t on = bip388_key_origin_format(&ki->origin, obuf, sizeof(obuf));
        bip388_sbuf_push(&b, obuf, on);
        bip388_sbuf_pushc(&b, ']');
    }
    char buf[120];
    size_t n = bip388_xpub_to_str(&ki->xpub, buf, sizeof(buf));
    bip388_sbuf_push(&b, buf, n);
    size_t needed = b.len;
    if (cap >= needed + 1) {
        memcpy(out, b.data, needed);
        out[needed] = '\0';
    }
    bip388_sbuf_free(&b);
    return needed;
}
