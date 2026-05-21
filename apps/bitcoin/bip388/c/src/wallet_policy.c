#include "../include/bip388.h"

#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ============================================================ */
/* VarInt (bitcoin consensus)                                   */
/* ============================================================ */

static bip388_err_t buf_push(uint8_t **out, size_t *cap, size_t *len, const uint8_t *data, size_t n) {
    if (*len + n > *cap) {
        size_t new_cap = *cap ? *cap : 64;
        while (new_cap < *len + n) new_cap *= 2;
        uint8_t *p = (uint8_t *)realloc(*out, new_cap);
        if (!p) return BIP388_ERR_NO_MEMORY;
        *out = p;
        *cap = new_cap;
    }
    memcpy(*out + *len, data, n);
    *len += n;
    return BIP388_OK;
}

static bip388_err_t varint_encode(uint8_t **out, size_t *cap, size_t *len, uint64_t n) {
    uint8_t buf[9];
    size_t sz;
    if (n < 0xFD) { buf[0] = (uint8_t)n; sz = 1; }
    else if (n <= 0xFFFFu) { buf[0] = 0xFD; buf[1] = (uint8_t)n; buf[2] = (uint8_t)(n >> 8); sz = 3; }
    else if (n <= 0xFFFFFFFFu) {
        buf[0] = 0xFE;
        for (int i = 0; i < 4; ++i) buf[1 + i] = (uint8_t)(n >> (i * 8));
        sz = 5;
    } else {
        buf[0] = 0xFF;
        for (int i = 0; i < 8; ++i) buf[1 + i] = (uint8_t)(n >> (i * 8));
        sz = 9;
    }
    return buf_push(out, cap, len, buf, sz);
}

typedef struct {
    const uint8_t *buf;
    size_t pos;
    size_t len;
} bip388_reader_t;

static bip388_err_t reader_read(bip388_reader_t *r, uint8_t *out, size_t n) {
    if (r->pos + n > r->len) return BIP388_ERR_DESERIALIZE;
    memcpy(out, r->buf + r->pos, n);
    r->pos += n;
    return BIP388_OK;
}

static bip388_err_t reader_read_varint(bip388_reader_t *r, uint64_t *out) {
    uint8_t b;
    bip388_err_t err = reader_read(r, &b, 1);
    if (err) return err;
    if (b < 0xFD) { *out = b; return BIP388_OK; }
    uint8_t tmp[8];
    if (b == 0xFD) {
        err = reader_read(r, tmp, 2);
        if (err) return err;
        *out = (uint64_t)tmp[0] | ((uint64_t)tmp[1] << 8);
        return BIP388_OK;
    }
    if (b == 0xFE) {
        err = reader_read(r, tmp, 4);
        if (err) return err;
        *out = 0;
        for (int i = 0; i < 4; ++i) *out |= (uint64_t)tmp[i] << (i * 8);
        return BIP388_OK;
    }
    err = reader_read(r, tmp, 8);
    if (err) return err;
    *out = 0;
    for (int i = 0; i < 8; ++i) *out |= (uint64_t)tmp[i] << (i * 8);
    return BIP388_OK;
}

/* ============================================================ */
/* WalletPolicy                                                 */
/* ============================================================ */

void bip388_wp_free(bip388_wallet_policy_t *wp) {
    if (!wp) return;
    if (wp->descriptor_template) {
        bip388_dt_free(wp->descriptor_template);
        free(wp->descriptor_template);
        wp->descriptor_template = NULL;
    }
    free(wp->descriptor_template_raw);
    wp->descriptor_template_raw = NULL;
    if (wp->key_information) {
        for (size_t i = 0; i < wp->n_key_information; ++i)
            bip388_key_info_free(&wp->key_information[i]);
        free(wp->key_information);
        wp->key_information = NULL;
    }
    wp->n_key_information = 0;
}

bip388_err_t bip388_wp_new(const char *desc_template,
                           const bip388_key_info_t *keys, size_t n_keys,
                           bip388_wallet_policy_t *out) {
    memset(out, 0, sizeof(*out));
    bip388_err_t err = bip388_dt_from_str(desc_template, &out->descriptor_template);
    if (err) return err;
    size_t slen = strlen(desc_template);
    out->descriptor_template_raw = (char *)malloc(slen + 1);
    if (!out->descriptor_template_raw) goto oom;
    memcpy(out->descriptor_template_raw, desc_template, slen + 1);
    if (n_keys) {
        out->key_information = (bip388_key_info_t *)calloc(n_keys, sizeof(*out->key_information));
        if (!out->key_information) goto oom;
        out->n_key_information = n_keys;
        for (size_t i = 0; i < n_keys; ++i) {
            bip388_key_info_t *src = (bip388_key_info_t *)&keys[i];
            bip388_key_info_t *dst = &out->key_information[i];
            dst->xpub = src->xpub;
            dst->has_origin = src->has_origin;
            if (src->has_origin) {
                dst->origin.fingerprint = src->origin.fingerprint;
                dst->origin.n_path = src->origin.n_path;
                if (src->origin.n_path) {
                    dst->origin.path = (uint32_t *)malloc(src->origin.n_path * sizeof(uint32_t));
                    if (!dst->origin.path) goto oom;
                    memcpy(dst->origin.path, src->origin.path,
                           src->origin.n_path * sizeof(uint32_t));
                }
            }
        }
    }
    return BIP388_OK;
oom:
    bip388_wp_free(out);
    return BIP388_ERR_NO_MEMORY;
}

bip388_err_t bip388_wp_segwit_version(const bip388_wallet_policy_t *wp, bip388_segwit_t *out) {
    const bip388_dt_t *dt = wp->descriptor_template;
    switch (dt->kind) {
        case BIP388_DT_TR:   *out = BIP388_SW_TAPROOT;   return BIP388_OK;
        case BIP388_DT_PKH:  *out = BIP388_SW_LEGACY;    return BIP388_OK;
        case BIP388_DT_WPKH:
        case BIP388_DT_WSH:  *out = BIP388_SW_SEGWIT_V0; return BIP388_OK;
        case BIP388_DT_SH: {
            bip388_dt_kind_t ik = dt->u.inner->kind;
            if (ik == BIP388_DT_WPKH || ik == BIP388_DT_WSH) {
                *out = BIP388_SW_SEGWIT_V0;
            } else {
                *out = BIP388_SW_LEGACY;
            }
            return BIP388_OK;
        }
        default: return BIP388_ERR_INVALID_TOP_LEVEL_POLICY;
    }
}

bip388_err_t bip388_wp_serialize(const bip388_wallet_policy_t *wp,
                                 uint8_t **out, size_t *out_len) {
    uint8_t *buf = NULL;
    size_t cap = 0, len = 0;
    size_t raw_len = strlen(wp->descriptor_template_raw);
    bip388_err_t err = varint_encode(&buf, &cap, &len, (uint64_t)raw_len);
    if (err) goto fail;
    err = buf_push(&buf, &cap, &len, (const uint8_t *)wp->descriptor_template_raw, raw_len);
    if (err) goto fail;
    err = varint_encode(&buf, &cap, &len, (uint64_t)wp->n_key_information);
    if (err) goto fail;
    for (size_t i = 0; i < wp->n_key_information; ++i) {
        const bip388_key_info_t *ki = &wp->key_information[i];
        uint8_t flag = ki->has_origin ? 1 : 0;
        err = buf_push(&buf, &cap, &len, &flag, 1);
        if (err) goto fail;
        if (ki->has_origin) {
            uint8_t fp[4];
            for (int j = 0; j < 4; ++j) fp[j] = (uint8_t)(ki->origin.fingerprint >> ((3 - j) * 8));
            err = buf_push(&buf, &cap, &len, fp, 4);
            if (err) goto fail;
            err = varint_encode(&buf, &cap, &len, (uint64_t)ki->origin.n_path);
            if (err) goto fail;
            for (size_t j = 0; j < ki->origin.n_path; ++j) {
                uint8_t s[4];
                for (int k = 0; k < 4; ++k) s[k] = (uint8_t)(ki->origin.path[j] >> (k * 8));
                err = buf_push(&buf, &cap, &len, s, 4);
                if (err) goto fail;
            }
        }
        err = buf_push(&buf, &cap, &len, ki->xpub.raw, 78);
        if (err) goto fail;
    }
    *out = buf;
    *out_len = len;
    return BIP388_OK;
fail:
    free(buf);
    return err;
}

bip388_err_t bip388_wp_deserialize(const uint8_t *data, size_t len,
                                   bip388_wallet_policy_t *out) {
    memset(out, 0, sizeof(*out));
    bip388_reader_t r = { .buf = data, .pos = 0, .len = len };
    uint64_t desc_len;
    bip388_err_t err = reader_read_varint(&r, &desc_len);
    if (err) return err;
    if (desc_len > BIP388_MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN)
        return BIP388_ERR_DESERIALIZE;
    char *desc_str = (char *)malloc(desc_len + 1);
    if (!desc_str) return BIP388_ERR_NO_MEMORY;
    err = reader_read(&r, (uint8_t *)desc_str, desc_len);
    if (err) { free(desc_str); return err; }
    desc_str[desc_len] = '\0';

    uint64_t n_keys;
    err = reader_read_varint(&r, &n_keys);
    if (err) { free(desc_str); return err; }
    if (n_keys > BIP388_MAX_SERIALIZED_KEY_COUNT) { free(desc_str); return BIP388_ERR_DESERIALIZE; }
    bip388_key_info_t *keys = NULL;
    if (n_keys) {
        keys = (bip388_key_info_t *)calloc(n_keys, sizeof(*keys));
        if (!keys) { free(desc_str); return BIP388_ERR_NO_MEMORY; }
    }
    for (size_t i = 0; i < n_keys; ++i) {
        uint8_t flag;
        err = reader_read(&r, &flag, 1);
        if (err) goto fail;
        if (flag == 0) {
            keys[i].has_origin = false;
        } else if (flag == 1) {
            keys[i].has_origin = true;
            uint8_t fp[4];
            err = reader_read(&r, fp, 4);
            if (err) goto fail;
            keys[i].origin.fingerprint = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16)
                                       | ((uint32_t)fp[2] << 8) | (uint32_t)fp[3];
            uint64_t dp_len;
            err = reader_read_varint(&r, &dp_len);
            if (err) goto fail;
            if (dp_len > BIP388_MAX_BIP32_DERIVATION_PATH_LEN - 2) {
                err = BIP388_ERR_DESERIALIZE; goto fail;
            }
            keys[i].origin.n_path = (size_t)dp_len;
            if (dp_len) {
                keys[i].origin.path = (uint32_t *)malloc(dp_len * sizeof(uint32_t));
                if (!keys[i].origin.path) { err = BIP388_ERR_NO_MEMORY; goto fail; }
                for (size_t j = 0; j < dp_len; ++j) {
                    uint8_t s[4];
                    err = reader_read(&r, s, 4);
                    if (err) goto fail;
                    keys[i].origin.path[j] = (uint32_t)s[0] | ((uint32_t)s[1] << 8)
                                            | ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
                }
            }
        } else {
            err = BIP388_ERR_DESERIALIZE; goto fail;
        }
        err = reader_read(&r, keys[i].xpub.raw, 78);
        if (err) goto fail;
    }

    if (r.pos != r.len) { err = BIP388_ERR_DESERIALIZE; goto fail; }

    err = bip388_wp_new(desc_str, keys, (size_t)n_keys, out);
    /* bip388_wp_new copied everything; free locals. */
    for (size_t i = 0; i < n_keys; ++i) bip388_key_info_free(&keys[i]);
    free(keys);
    free(desc_str);
    if (err == BIP388_ERR_NO_MEMORY) return err;
    if (err) return BIP388_ERR_DESERIALIZE;
    return BIP388_OK;

fail:
    for (size_t i = 0; i < n_keys; ++i) bip388_key_info_free(&keys[i]);
    free(keys);
    free(desc_str);
    return err;
}
