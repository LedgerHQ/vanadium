/* DescriptorTemplate parser, display, placeholders, and rendering with
 * concrete key information. Mirrors src/lib.rs of the Rust crate.
 */

#include "../include/bip388.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

/* ============================================================ */
/* Free helpers                                                 */
/* ============================================================ */

void bip388_ke_free(bip388_ke_t *ke) {
    if (!ke) return;
    if (ke->type == BIP388_KE_MUSIG) {
        free(ke->u.musig.indices);
        ke->u.musig.indices = NULL;
        ke->u.musig.n_indices = 0;
    }
}

void bip388_dt_free(bip388_dt_t *dt) {
    if (!dt) return;
    switch (dt->kind) {
        case BIP388_DT_ZERO:
        case BIP388_DT_ONE:
        case BIP388_DT_OLDER:
        case BIP388_DT_AFTER:
        case BIP388_DT_SHA256:
        case BIP388_DT_HASH256:
        case BIP388_DT_RIPEMD160:
        case BIP388_DT_HASH160:
            break;
        case BIP388_DT_SH:
        case BIP388_DT_WSH:
        case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
        case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
        case BIP388_DT_L: case BIP388_DT_U:
            bip388_dt_free(dt->u.inner);
            free(dt->u.inner);
            break;
        case BIP388_DT_PKH: case BIP388_DT_WPKH:
        case BIP388_DT_PK:  case BIP388_DT_PK_K: case BIP388_DT_PK_H:
            bip388_ke_free(&dt->u.key);
            break;
        case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
        case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A:
            for (size_t i = 0; i < dt->u.multi.n_keys; ++i)
                bip388_ke_free(&dt->u.multi.keys[i]);
            free(dt->u.multi.keys);
            break;
        case BIP388_DT_THRESH:
            for (size_t i = 0; i < dt->u.thresh.n_subs; ++i) {
                bip388_dt_free(dt->u.thresh.subs[i]);
                free(dt->u.thresh.subs[i]);
            }
            free(dt->u.thresh.subs);
            break;
        case BIP388_DT_ANDOR:
            bip388_dt_free(dt->u.trio.x); free(dt->u.trio.x);
            bip388_dt_free(dt->u.trio.y); free(dt->u.trio.y);
            bip388_dt_free(dt->u.trio.z); free(dt->u.trio.z);
            break;
        case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
        case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I:
            bip388_dt_free(dt->u.pair.x); free(dt->u.pair.x);
            bip388_dt_free(dt->u.pair.y); free(dt->u.pair.y);
            break;
        case BIP388_DT_TR:
            bip388_ke_free(&dt->u.tr.key);
            if (dt->u.tr.tree) {
                bip388_tt_free(dt->u.tr.tree);
                free(dt->u.tr.tree);
            }
            break;
    }
}

void bip388_tt_free(bip388_tap_tree_t *tt) {
    if (!tt) return;
    if (tt->kind == BIP388_TT_SCRIPT) {
        bip388_dt_free(tt->u.script);
        free(tt->u.script);
    } else {
        bip388_tt_free(tt->u.branch.left);
        free(tt->u.branch.left);
        bip388_tt_free(tt->u.branch.right);
        free(tt->u.branch.right);
    }
}

/* ============================================================ */
/* Key expression helpers                                       */
/* ============================================================ */

void bip388_ke_init_plain(bip388_ke_t *ke, uint32_t idx, uint32_t n1, uint32_t n2) {
    ke->type = BIP388_KE_PLAIN;
    ke->num1 = n1;
    ke->num2 = n2;
    ke->u.plain_index = idx;
}

bip388_err_t bip388_ke_init_musig(bip388_ke_t *ke, const uint32_t *idx, size_t n,
                                  uint32_t n1, uint32_t n2) {
    ke->type = BIP388_KE_MUSIG;
    ke->num1 = n1;
    ke->num2 = n2;
    ke->u.musig.indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!ke->u.musig.indices) return BIP388_ERR_NO_MEMORY;
    memcpy(ke->u.musig.indices, idx, n * sizeof(uint32_t));
    ke->u.musig.n_indices = n;
    return BIP388_OK;
}

bool bip388_ke_equal(const bip388_ke_t *a, const bip388_ke_t *b) {
    if (a->type != b->type || a->num1 != b->num1 || a->num2 != b->num2) return false;
    if (a->type == BIP388_KE_PLAIN) return a->u.plain_index == b->u.plain_index;
    if (a->u.musig.n_indices != b->u.musig.n_indices) return false;
    return memcmp(a->u.musig.indices, b->u.musig.indices,
                  a->u.musig.n_indices * sizeof(uint32_t)) == 0;
}

/* ============================================================ */
/* Display                                                      */
/* ============================================================ */

static bip388_err_t ke_to_sbuf(const bip388_ke_t *ke, bip388_sbuf_t *b) {
    if (ke->type == BIP388_KE_PLAIN) {
        if (ke->num1 == 0 && ke->num2 == 1)
            return bip388_sbuf_pushf(b, "@%u/**", ke->u.plain_index);
        return bip388_sbuf_pushf(b, "@%u/<%u;%u>/*", ke->u.plain_index, ke->num1, ke->num2);
    }
    bip388_err_t err = bip388_sbuf_push(b, BIP388_LIT("musig("));
    if (err) return err;
    for (size_t i = 0; i < ke->u.musig.n_indices; ++i) {
        if (i > 0) {
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
        }
        err = bip388_sbuf_pushf(b, "@%u", ke->u.musig.indices[i]);
        if (err) return err;
    }
    if (ke->num1 == 0 && ke->num2 == 1)
        return bip388_sbuf_push(b, BIP388_LIT(")/**"));
    return bip388_sbuf_pushf(b, ")/<%u;%u>/*", ke->num1, ke->num2);
}

static size_t hash_len_for_kind(bip388_dt_kind_t k) {
    if (k == BIP388_DT_SHA256 || k == BIP388_DT_HASH256) return 32;
    return 20;
}

static bip388_err_t dt_to_sbuf(const bip388_dt_t *dt, bip388_sbuf_t *b);
static bip388_err_t tt_to_sbuf(const bip388_tap_tree_t *tt, bip388_sbuf_t *b);

static bip388_err_t dt_to_sbuf(const bip388_dt_t *dt, bip388_sbuf_t *b) {
    const char *name = bip388_kind_lower(dt->kind);
    bip388_err_t err;
    switch (dt->kind) {
        case BIP388_DT_ZERO: return bip388_sbuf_pushc(b, '0');
        case BIP388_DT_ONE:  return bip388_sbuf_pushc(b, '1');
        case BIP388_DT_OLDER:
        case BIP388_DT_AFTER:
            return bip388_sbuf_pushf(b, "%s(%u)", name, dt->u.num);
        case BIP388_DT_SHA256:
        case BIP388_DT_HASH256:
        case BIP388_DT_RIPEMD160:
        case BIP388_DT_HASH160: {
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            size_t hlen = hash_len_for_kind(dt->kind);
            for (size_t i = 0; i < hlen; ++i) {
                err = bip388_sbuf_pushf(b, "%02x", dt->u.hash[i]);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        }
        case BIP388_DT_PKH: case BIP388_DT_WPKH:
        case BIP388_DT_PK:  case BIP388_DT_PK_K: case BIP388_DT_PK_H:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = ke_to_sbuf(&dt->u.key, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_SH: case BIP388_DT_WSH:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = dt_to_sbuf(dt->u.inner, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
        case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
        case BIP388_DT_L: case BIP388_DT_U: {
            char c = bip388_wrapper_to_char(dt->kind);
            err = bip388_sbuf_pushc(b, c);
            if (err) return err;
            if (!bip388_kind_is_wrapper(dt->u.inner->kind)) {
                err = bip388_sbuf_pushc(b, ':');
                if (err) return err;
            }
            return dt_to_sbuf(dt->u.inner, b);
        }
        case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
        case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A:
            err = bip388_sbuf_pushf(b, "%s(%u", name, dt->u.multi.threshold);
            if (err) return err;
            for (size_t i = 0; i < dt->u.multi.n_keys; ++i) {
                err = bip388_sbuf_pushc(b, ',');
                if (err) return err;
                err = ke_to_sbuf(&dt->u.multi.keys[i], b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_THRESH:
            err = bip388_sbuf_pushf(b, "thresh(%u", dt->u.thresh.threshold);
            if (err) return err;
            for (size_t i = 0; i < dt->u.thresh.n_subs; ++i) {
                err = bip388_sbuf_pushc(b, ',');
                if (err) return err;
                err = dt_to_sbuf(dt->u.thresh.subs[i], b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_ANDOR:
            err = bip388_sbuf_push(b, BIP388_LIT("andor("));
            if (err) return err;
            err = dt_to_sbuf(dt->u.trio.x, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_sbuf(dt->u.trio.y, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_sbuf(dt->u.trio.z, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
        case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = dt_to_sbuf(dt->u.pair.x, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_sbuf(dt->u.pair.y, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_TR:
            err = bip388_sbuf_push(b, BIP388_LIT("tr("));
            if (err) return err;
            err = ke_to_sbuf(&dt->u.tr.key, b);
            if (err) return err;
            if (dt->u.tr.tree) {
                err = bip388_sbuf_pushc(b, ',');
                if (err) return err;
                err = tt_to_sbuf(dt->u.tr.tree, b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
    }
    return BIP388_ERR_FORMAT_ERROR;
}

static bip388_err_t tt_to_sbuf(const bip388_tap_tree_t *tt, bip388_sbuf_t *b) {
    if (tt->kind == BIP388_TT_SCRIPT) return dt_to_sbuf(tt->u.script, b);
    bip388_err_t err = bip388_sbuf_pushc(b, '{');
    if (err) return err;
    err = tt_to_sbuf(tt->u.branch.left, b);
    if (err) return err;
    err = bip388_sbuf_pushc(b, ',');
    if (err) return err;
    err = tt_to_sbuf(tt->u.branch.right, b);
    if (err) return err;
    return bip388_sbuf_pushc(b, '}');
}

static size_t sbuf_copy_out(bip388_sbuf_t *b, char *out, size_t cap) {
    size_t needed = b->len;
    if (cap >= needed + 1) {
        memcpy(out, b->data, needed);
        out[needed] = '\0';
    }
    return needed;
}

size_t bip388_dt_format(const bip388_dt_t *dt, char *out, size_t cap) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    if (dt_to_sbuf(dt, &b) != BIP388_OK) {
        bip388_sbuf_free(&b);
        return 0;
    }
    size_t r = sbuf_copy_out(&b, out, cap);
    bip388_sbuf_free(&b);
    return r;
}

size_t bip388_tt_format(const bip388_tap_tree_t *tt, char *out, size_t cap) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    if (tt_to_sbuf(tt, &b) != BIP388_OK) {
        bip388_sbuf_free(&b);
        return 0;
    }
    size_t r = sbuf_copy_out(&b, out, cap);
    bip388_sbuf_free(&b);
    return r;
}

size_t bip388_ke_format(const bip388_ke_t *ke, char *out, size_t cap) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    if (ke_to_sbuf(ke, &b) != BIP388_OK) {
        bip388_sbuf_free(&b);
        return 0;
    }
    size_t r = sbuf_copy_out(&b, out, cap);
    bip388_sbuf_free(&b);
    return r;
}

/* ============================================================ */
/* Parser                                                       */
/* ============================================================ */

static bip388_err_t parse_number_up_to(bip388_parser_t *p, uint32_t max, uint32_t *out) {
    if (p->pos >= p->len || !isdigit((unsigned char)p->src[p->pos]))
        return BIP388_ERR_INVALID_SYNTAX;
    if (p->src[p->pos] == '0' && p->pos + 1 < p->len &&
        isdigit((unsigned char)p->src[p->pos + 1]))
        return BIP388_ERR_NUMBER_OUT_OF_RANGE;
    uint64_t val = 0;
    while (p->pos < p->len && isdigit((unsigned char)p->src[p->pos])) {
        val = val * 10 + (uint64_t)(p->src[p->pos] - '0');
        if (val > 0xFFFFFFFFu) return BIP388_ERR_NUMBER_OUT_OF_RANGE;
        p->pos++;
    }
    if (val > max) return BIP388_ERR_NUMBER_OUT_OF_RANGE;
    *out = (uint32_t)val;
    return BIP388_OK;
}

static bip388_err_t parse_derivation_step_number(bip388_parser_t *p, uint32_t *out) {
    bip388_err_t err = parse_number_up_to(p, BIP388_HARDENED_INDEX - 1, out);
    if (err) return err;
    if (bip388_p_try(p, '\'')) *out += BIP388_HARDENED_INDEX;
    return BIP388_OK;
}

static bip388_err_t parse_derivation_suffix(bip388_parser_t *p, uint32_t *n1, uint32_t *n2) {
    if (!bip388_p_try(p, '/')) return BIP388_ERR_INVALID_SYNTAX;
    if (bip388_p_starts_with(p, BIP388_LIT("**"))) {
        p->pos += 2;
        *n1 = 0;
        *n2 = 1;
        return BIP388_OK;
    }
    if (!bip388_p_try(p, '<')) return BIP388_ERR_INVALID_SYNTAX;
    bip388_err_t err = parse_derivation_step_number(p, n1);
    if (err) return err;
    if (!bip388_p_try(p, ';')) return BIP388_ERR_INVALID_SYNTAX;
    err = parse_derivation_step_number(p, n2);
    if (err) return err;
    if (!bip388_p_starts_with(p, BIP388_LIT(">/*"))) return BIP388_ERR_INVALID_SYNTAX;
    p->pos += 3;
    return BIP388_OK;
}

static bip388_err_t parse_musig_key_expression(bip388_parser_t *p, bip388_ke_t *out) {
    p->pos += 6; /* "musig(" */
    uint32_t *indices = NULL;
    size_t n_indices = 0, cap = 0;
    bip388_err_t err;
    while (1) {
        if (!bip388_p_try(p, '@')) { err = BIP388_ERR_INVALID_SYNTAX; goto fail; }
        uint32_t idx;
        err = parse_number_up_to(p, 0xFFFFFFFFu, &idx);
        if (err) goto fail;
        for (size_t i = 0; i < n_indices; ++i) {
            if (indices[i] == idx) { err = BIP388_ERR_INVALID_KEY; goto fail; }
        }
        if (n_indices == cap) {
            size_t new_cap = cap ? cap * 2 : 4;
            uint32_t *np = (uint32_t *)realloc(indices, new_cap * sizeof(uint32_t));
            if (!np) { err = BIP388_ERR_NO_MEMORY; goto fail; }
            indices = np;
            cap = new_cap;
        }
        indices[n_indices++] = idx;
        if (!bip388_p_try(p, ',')) break;
    }
    if (n_indices < 2) { err = BIP388_ERR_TOO_FEW_KEY_EXPRESSIONS; goto fail; }
    if (!bip388_p_try(p, ')')) { err = BIP388_ERR_INVALID_SYNTAX; goto fail; }
    uint32_t n1, n2;
    err = parse_derivation_suffix(p, &n1, &n2);
    if (err) goto fail;
    out->type = BIP388_KE_MUSIG;
    out->num1 = n1;
    out->num2 = n2;
    out->u.musig.indices = indices;
    out->u.musig.n_indices = n_indices;
    return BIP388_OK;
fail:
    free(indices);
    return err;
}

static bip388_err_t parse_key_expression(bip388_parser_t *p, bip388_ctx_t ctx, bip388_ke_t *out) {
    if (bip388_p_starts_with(p, BIP388_LIT("musig("))) {
        if (!bip388_ctx_musig_allowed(ctx)) return BIP388_ERR_INVALID_SCRIPT_CONTEXT;
        return parse_musig_key_expression(p, out);
    }
    if (!bip388_p_try(p, '@')) return BIP388_ERR_INVALID_SYNTAX;
    uint32_t idx;
    bip388_err_t err = parse_number_up_to(p, 0xFFFFFFFFu, &idx);
    if (err) return err;
    uint32_t n1, n2;
    err = parse_derivation_suffix(p, &n1, &n2);
    if (err) return err;
    bip388_ke_init_plain(out, idx, n1, n2);
    return BIP388_OK;
}

/* Forward decl */
static bip388_err_t parse_descriptor(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth, bip388_dt_t **out);
static bip388_err_t parse_inner_descriptor(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth, bip388_dt_t **out);
static bip388_err_t parse_thresh(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth, bip388_dt_t **out);
static bip388_err_t parse_tr(bip388_parser_t *p, size_t depth, bip388_dt_t **out);
static bip388_err_t parse_tap_tree(bip388_parser_t *p, size_t depth, bip388_tap_tree_t **out);

static bip388_dt_t *alloc_dt(bip388_dt_kind_t k) {
    bip388_dt_t *dt = (bip388_dt_t *)calloc(1, sizeof(*dt));
    if (dt) dt->kind = k;
    return dt;
}

static bip388_err_t parse_n_subscripts(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth,
                                       size_t n, bip388_dt_t **subs_out /* n entries */) {
    bip388_err_t saved = BIP388_ERR_INVALID_SYNTAX;
    for (size_t i = 0; i < n; ++i) subs_out[i] = NULL;
    for (size_t i = 0; i < n; ++i) {
        bip388_err_t err = parse_descriptor(p, ctx, depth, &subs_out[i]);
        if (err) { saved = err; goto fail; }
        if (i + 1 < n) {
            if (!bip388_p_try(p, ',')) goto fail;
        }
    }
    if (!bip388_p_try(p, ')')) goto fail;
    return BIP388_OK;
fail:
    for (size_t i = 0; i < n; ++i) {
        if (subs_out[i]) { bip388_dt_free(subs_out[i]); free(subs_out[i]); subs_out[i] = NULL; }
    }
    return saved;
}

static bip388_err_t parse_kp_fragment(bip388_parser_t *p, size_t name_len,
                                      bip388_dt_kind_t kind, bip388_ctx_t ctx,
                                      bip388_dt_t **out) {
    p->pos += name_len + 1; /* skip name + '(' */
    bip388_ke_t ke = {0};
    bip388_err_t err = parse_key_expression(p, ctx, &ke);
    if (err) return err;
    if (!bip388_p_try(p, ')')) { bip388_ke_free(&ke); return BIP388_ERR_INVALID_SYNTAX; }
    bip388_dt_t *dt = alloc_dt(kind);
    if (!dt) { bip388_ke_free(&ke); return BIP388_ERR_NO_MEMORY; }
    dt->u.key = ke;
    *out = dt;
    return BIP388_OK;
}

static bip388_err_t parse_num_fragment(bip388_parser_t *p, size_t name_len, uint32_t max,
                                       bip388_dt_kind_t kind, bip388_dt_t **out) {
    p->pos += name_len + 1;
    uint32_t n;
    bip388_err_t err = parse_number_up_to(p, max, &n);
    if (err) return err;
    if (!bip388_p_try(p, ')')) return BIP388_ERR_INVALID_SYNTAX;
    bip388_dt_t *dt = alloc_dt(kind);
    if (!dt) return BIP388_ERR_NO_MEMORY;
    dt->u.num = n;
    *out = dt;
    return BIP388_OK;
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

static bip388_err_t parse_hex_fragment(bip388_parser_t *p, size_t name_len, size_t n_bytes,
                                       bip388_dt_kind_t kind, bip388_dt_t **out) {
    p->pos += name_len + 1;
    size_t hex_len = n_bytes * 2;
    if (p->pos + hex_len > p->len) return BIP388_ERR_INVALID_LENGTH;
    uint8_t buf[32];
    for (size_t i = 0; i < n_bytes; ++i) {
        int hi = hex_nibble(p->src[p->pos + 2 * i]);
        int lo = hex_nibble(p->src[p->pos + 2 * i + 1]);
        if (hi < 0 || lo < 0) return BIP388_ERR_INVALID_HEX;
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    p->pos += hex_len;
    if (!bip388_p_try(p, ')')) return BIP388_ERR_INVALID_SYNTAX;
    bip388_dt_t *dt = alloc_dt(kind);
    if (!dt) return BIP388_ERR_NO_MEMORY;
    memset(dt->u.hash, 0, 32);
    memcpy(dt->u.hash, buf, n_bytes);
    *out = dt;
    return BIP388_OK;
}

static bip388_err_t parse_threshold_kp_fragment(bip388_parser_t *p, size_t name_len,
                                                bip388_dt_kind_t kind, bip388_ctx_t ctx,
                                                size_t max_keys, bip388_dt_t **out) {
    p->pos += name_len + 1;
    uint32_t threshold;
    bip388_err_t err = parse_number_up_to(p, 0xFFFFFFFFu, &threshold);
    if (err) return err;
    bip388_ke_t *keys = NULL;
    size_t n_keys = 0, cap = 0;
    while (1) {
        if (p->pos >= p->len || p->src[p->pos] != ',') break;
        if (n_keys >= max_keys) { err = BIP388_ERR_TOO_MANY_KEYS; goto fail; }
        size_t save = p->pos;
        p->pos++; /* consume ',' */
        bip388_ke_t ke = {0};
        err = parse_key_expression(p, ctx, &ke);
        if (err == BIP388_OK) {
            if (n_keys == cap) {
                size_t new_cap = cap ? cap * 2 : 4;
                bip388_ke_t *np = (bip388_ke_t *)realloc(keys, new_cap * sizeof(bip388_ke_t));
                if (!np) { bip388_ke_free(&ke); err = BIP388_ERR_NO_MEMORY; goto fail; }
                keys = np;
                cap = new_cap;
            }
            keys[n_keys++] = ke;
            continue;
        }
        if (err == BIP388_ERR_INVALID_SCRIPT_CONTEXT) goto fail;
        /* On other errors, restore position and stop the loop. */
        p->pos = save;
        err = BIP388_OK;
        break;
    }
    if (n_keys < 2) { err = BIP388_ERR_TOO_FEW_KEY_EXPRESSIONS; goto fail; }
    if (threshold == 0 || threshold > n_keys) {
        err = BIP388_ERR_INVALID_MULTISIG_QUORUM;
        goto fail;
    }
    if (!bip388_p_try(p, ')')) { err = BIP388_ERR_INVALID_SYNTAX; goto fail; }
    bip388_dt_t *dt = alloc_dt(kind);
    if (!dt) { err = BIP388_ERR_NO_MEMORY; goto fail; }
    dt->u.multi.threshold = threshold;
    dt->u.multi.keys = keys;
    dt->u.multi.n_keys = n_keys;
    *out = dt;
    return BIP388_OK;
fail:
    for (size_t i = 0; i < n_keys; ++i) bip388_ke_free(&keys[i]);
    free(keys);
    return err;
}

static bip388_err_t parse_thresh(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth,
                                 bip388_dt_t **out) {
    p->pos += 7; /* "thresh(" */
    uint32_t k;
    bip388_err_t err = parse_number_up_to(p, 0xFFFFFFFFu, &k);
    if (err) return err;
    if (!bip388_p_try(p, ',')) return BIP388_ERR_INVALID_SYNTAX;
    bip388_dt_t **subs = NULL;
    size_t n_subs = 0, cap = 0;
    bip388_dt_t *first = NULL;
    err = parse_descriptor(p, ctx, depth, &first);
    if (err) return err;
    /* push first */
    subs = (bip388_dt_t **)malloc(sizeof(*subs) * 4);
    if (!subs) { bip388_dt_free(first); free(first); return BIP388_ERR_NO_MEMORY; }
    cap = 4;
    subs[n_subs++] = first;
    while (1) {
        if (p->pos >= p->len || p->src[p->pos] != ',') break;
        size_t save = p->pos;
        p->pos++;
        bip388_dt_t *d = NULL;
        err = parse_descriptor(p, ctx, depth, &d);
        if (err == BIP388_OK) {
            if (n_subs == cap) {
                size_t new_cap = cap * 2;
                bip388_dt_t **np = (bip388_dt_t **)realloc(subs, new_cap * sizeof(*np));
                if (!np) { bip388_dt_free(d); free(d); err = BIP388_ERR_NO_MEMORY; goto fail; }
                subs = np;
                cap = new_cap;
            }
            subs[n_subs++] = d;
            continue;
        }
        if (err == BIP388_ERR_NESTING_TOO_DEEP) goto fail;
        p->pos = save;
        err = BIP388_OK;
        break;
    }
    if (k == 0) { err = BIP388_ERR_INVALID_MULTISIG_QUORUM; goto fail; }
    if (k > n_subs) { err = BIP388_ERR_THRESH_EXCEEDS_SCRIPTS; goto fail; }
    if (!bip388_p_try(p, ')')) { err = BIP388_ERR_INVALID_SYNTAX; goto fail; }
    bip388_dt_t *dt = alloc_dt(BIP388_DT_THRESH);
    if (!dt) { err = BIP388_ERR_NO_MEMORY; goto fail; }
    dt->u.thresh.threshold = k;
    dt->u.thresh.subs = subs;
    dt->u.thresh.n_subs = n_subs;
    *out = dt;
    return BIP388_OK;
fail:
    for (size_t i = 0; i < n_subs; ++i) { bip388_dt_free(subs[i]); free(subs[i]); }
    free(subs);
    return err;
}

static bip388_err_t parse_tr(bip388_parser_t *p, size_t depth, bip388_dt_t **out) {
    p->pos += 3; /* "tr(" */
    bip388_ke_t ke = {0};
    bip388_err_t err = parse_key_expression(p, BIP388_CTX_TAPROOT, &ke);
    if (err) return err;
    bip388_tap_tree_t *tree = NULL;
    if (bip388_p_try(p, ',')) {
        err = parse_tap_tree(p, depth, &tree);
        if (err) { bip388_ke_free(&ke); return err; }
    }
    if (!bip388_p_try(p, ')')) {
        bip388_ke_free(&ke);
        if (tree) { bip388_tt_free(tree); free(tree); }
        return BIP388_ERR_INVALID_SYNTAX;
    }
    bip388_dt_t *dt = alloc_dt(BIP388_DT_TR);
    if (!dt) {
        bip388_ke_free(&ke);
        if (tree) { bip388_tt_free(tree); free(tree); }
        return BIP388_ERR_NO_MEMORY;
    }
    dt->u.tr.key = ke;
    dt->u.tr.tree = tree;
    *out = dt;
    return BIP388_OK;
}

static bip388_err_t parse_tap_tree(bip388_parser_t *p, size_t depth, bip388_tap_tree_t **out) {
    if (depth >= BIP388_MAX_PARSE_DEPTH) return BIP388_ERR_NESTING_TOO_DEEP;
    depth++;
    if (bip388_p_try(p, '{')) {
        bip388_tap_tree_t *left = NULL, *right = NULL;
        bip388_err_t err = parse_tap_tree(p, depth, &left);
        if (err) return err;
        if (!bip388_p_try(p, ',')) {
            bip388_tt_free(left); free(left);
            return BIP388_ERR_INVALID_SYNTAX;
        }
        err = parse_tap_tree(p, depth, &right);
        if (err) { bip388_tt_free(left); free(left); return err; }
        if (!bip388_p_try(p, '}')) {
            bip388_tt_free(left); free(left);
            bip388_tt_free(right); free(right);
            return BIP388_ERR_INVALID_SYNTAX;
        }
        bip388_tap_tree_t *tt = (bip388_tap_tree_t *)calloc(1, sizeof(*tt));
        if (!tt) {
            bip388_tt_free(left); free(left);
            bip388_tt_free(right); free(right);
            return BIP388_ERR_NO_MEMORY;
        }
        tt->kind = BIP388_TT_BRANCH;
        tt->u.branch.left = left;
        tt->u.branch.right = right;
        *out = tt;
        return BIP388_OK;
    }
    bip388_dt_t *dt = NULL;
    bip388_err_t err = parse_descriptor(p, BIP388_CTX_TAPROOT, depth, &dt);
    if (err) return err;
    bip388_tap_tree_t *tt = (bip388_tap_tree_t *)calloc(1, sizeof(*tt));
    if (!tt) { bip388_dt_free(dt); free(dt); return BIP388_ERR_NO_MEMORY; }
    tt->kind = BIP388_TT_SCRIPT;
    tt->u.script = dt;
    *out = tt;
    return BIP388_OK;
}

/* Returns (parsed_dt) for descriptor, optionally wrapped by an "abc:" prefix. */
static bip388_err_t parse_descriptor(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth,
                                     bip388_dt_t **out) {
    if (depth >= BIP388_MAX_PARSE_DEPTH) return BIP388_ERR_NESTING_TOO_DEEP;
    depth++;
    /* Wrapper prefix: run of alphabetic chars followed by ':'. */
    size_t alpha_end = p->pos;
    while (alpha_end < p->len && isalpha((unsigned char)p->src[alpha_end])) alpha_end++;
    size_t wrappers_start = p->pos;
    size_t wrappers_len = 0;
    if (alpha_end > p->pos && alpha_end < p->len && p->src[alpha_end] == ':') {
        wrappers_len = alpha_end - p->pos;
        p->pos = alpha_end + 1;
    }
    bip388_dt_t *inner = NULL;
    bip388_err_t err = parse_inner_descriptor(p, ctx, depth, &inner);
    if (err) return err;
    /* Apply wrappers in reverse. */
    for (size_t i = 0; i < wrappers_len; ++i) {
        size_t idx = wrappers_len - 1 - i; /* iterate from end */
        char c = p->src[wrappers_start + idx];
        bip388_dt_kind_t k;
        if (!bip388_wrapper_from_char(c, &k)) {
            bip388_dt_free(inner); free(inner);
            return BIP388_ERR_INVALID_SYNTAX;
        }
        bip388_dt_t *w = alloc_dt(k);
        if (!w) { bip388_dt_free(inner); free(inner); return BIP388_ERR_NO_MEMORY; }
        w->u.inner = inner;
        inner = w;
    }
    *out = inner;
    return BIP388_OK;
}

static bip388_err_t parse_inner_descriptor(bip388_parser_t *p, bip388_ctx_t ctx, size_t depth,
                                           bip388_dt_t **out) {
    if (bip388_p_starts_with(p, BIP388_LIT("sortedmulti_a(")))
        return parse_threshold_kp_fragment(p, 13, BIP388_DT_SORTEDMULTI_A, ctx,
                                           BIP388_MAX_KEYS_MULTI_A, out);
    if (bip388_p_starts_with(p, BIP388_LIT("sortedmulti(")))
        return parse_threshold_kp_fragment(p, 11, BIP388_DT_SORTEDMULTI, ctx,
                                           BIP388_MAX_KEYS_MULTI, out);
    if (bip388_p_starts_with(p, BIP388_LIT("multi_a(")))
        return parse_threshold_kp_fragment(p, 7, BIP388_DT_MULTI_A, ctx,
                                           BIP388_MAX_KEYS_MULTI_A, out);
    if (bip388_p_starts_with(p, BIP388_LIT("multi(")))
        return parse_threshold_kp_fragment(p, 5, BIP388_DT_MULTI, ctx,
                                           BIP388_MAX_KEYS_MULTI, out);
    if (bip388_p_starts_with(p, BIP388_LIT("thresh(")))
        return parse_thresh(p, ctx, depth, out);
    if (bip388_p_starts_with(p, BIP388_LIT("wsh("))) {
        if (!bip388_ctx_wsh_allowed(ctx)) return BIP388_ERR_INVALID_SCRIPT_CONTEXT;
        bip388_ctx_t inner_ctx =
            (ctx == BIP388_CTX_TOP_LEVEL) ? BIP388_CTX_SEGWIT : BIP388_CTX_WRAPPED_SEGWIT;
        p->pos += 4;
        bip388_dt_t *sub = NULL;
        bip388_err_t err = parse_n_subscripts(p, inner_ctx, depth, 1, &sub);
        if (err) return err;
        bip388_dt_t *dt = alloc_dt(BIP388_DT_WSH);
        if (!dt) { bip388_dt_free(sub); free(sub); return BIP388_ERR_NO_MEMORY; }
        dt->u.inner = sub;
        *out = dt;
        return BIP388_OK;
    }
    if (bip388_p_starts_with(p, BIP388_LIT("sh("))) {
        if (!bip388_ctx_sh_allowed(ctx)) return BIP388_ERR_INVALID_SCRIPT_CONTEXT;
        p->pos += 3;
        bip388_dt_t *sub = NULL;
        bip388_err_t err = parse_n_subscripts(p, BIP388_CTX_LEGACY, depth, 1, &sub);
        if (err) return err;
        bip388_dt_t *dt = alloc_dt(BIP388_DT_SH);
        if (!dt) { bip388_dt_free(sub); free(sub); return BIP388_ERR_NO_MEMORY; }
        dt->u.inner = sub;
        *out = dt;
        return BIP388_OK;
    }
    if (bip388_p_starts_with(p, BIP388_LIT("wpkh("))) {
        if (!bip388_ctx_wpkh_allowed(ctx)) return BIP388_ERR_INVALID_SCRIPT_CONTEXT;
        return parse_kp_fragment(p, 4, BIP388_DT_WPKH, ctx, out);
    }
    if (bip388_p_starts_with(p, BIP388_LIT("pkh("))) {
        return parse_kp_fragment(p, 3, BIP388_DT_PKH, ctx, out);
    }
    if (bip388_p_starts_with(p, BIP388_LIT("tr("))) {
        if (!bip388_ctx_tr_allowed(ctx)) return BIP388_ERR_INVALID_SCRIPT_CONTEXT;
        return parse_tr(p, depth, out);
    }
    if (bip388_p_starts_with(p, BIP388_LIT("pk_k(")))
        return parse_kp_fragment(p, 4, BIP388_DT_PK_K, ctx, out);
    if (bip388_p_starts_with(p, BIP388_LIT("pk_h(")))
        return parse_kp_fragment(p, 4, BIP388_DT_PK_H, ctx, out);
    if (bip388_p_starts_with(p, BIP388_LIT("pk(")))
        return parse_kp_fragment(p, 2, BIP388_DT_PK, ctx, out);
    if (bip388_p_starts_with(p, BIP388_LIT("older(")))
        return parse_num_fragment(p, 5, BIP388_MAX_OLDER_AFTER, BIP388_DT_OLDER, out);
    if (bip388_p_starts_with(p, BIP388_LIT("after(")))
        return parse_num_fragment(p, 5, BIP388_MAX_OLDER_AFTER, BIP388_DT_AFTER, out);
    if (bip388_p_starts_with(p, BIP388_LIT("sha256(")))
        return parse_hex_fragment(p, 6, 32, BIP388_DT_SHA256, out);
    if (bip388_p_starts_with(p, BIP388_LIT("hash256(")))
        return parse_hex_fragment(p, 7, 32, BIP388_DT_HASH256, out);
    if (bip388_p_starts_with(p, BIP388_LIT("ripemd160(")))
        return parse_hex_fragment(p, 9, 20, BIP388_DT_RIPEMD160, out);
    if (bip388_p_starts_with(p, BIP388_LIT("hash160(")))
        return parse_hex_fragment(p, 7, 20, BIP388_DT_HASH160, out);
    if (bip388_p_starts_with(p, BIP388_LIT("andor("))) {
        p->pos += 6;
        bip388_dt_t *subs[3] = {0};
        bip388_err_t err = parse_n_subscripts(p, ctx, depth, 3, subs);
        if (err) return err;
        bip388_dt_t *dt = alloc_dt(BIP388_DT_ANDOR);
        if (!dt) {
            for (int i = 0; i < 3; ++i) { bip388_dt_free(subs[i]); free(subs[i]); }
            return BIP388_ERR_NO_MEMORY;
        }
        dt->u.trio.x = subs[0]; dt->u.trio.y = subs[1]; dt->u.trio.z = subs[2];
        *out = dt;
        return BIP388_OK;
    }
    /* Pair-arg fragments: and_b/and_v/and_n, or_b/or_c/or_d/or_i */
    struct pair_def {
        const char *prefix; size_t plen; bip388_dt_kind_t kind;
    };
    static const struct pair_def pairs[] = {
        {"and_b(", 6, BIP388_DT_AND_B},
        {"and_v(", 6, BIP388_DT_AND_V},
        {"and_n(", 6, BIP388_DT_AND_N},
        {"or_b(",  5, BIP388_DT_OR_B},
        {"or_c(",  5, BIP388_DT_OR_C},
        {"or_d(",  5, BIP388_DT_OR_D},
        {"or_i(",  5, BIP388_DT_OR_I},
    };
    for (size_t i = 0; i < sizeof(pairs) / sizeof(*pairs); ++i) {
        if (bip388_p_starts_with(p, pairs[i].prefix, pairs[i].plen)) {
            p->pos += pairs[i].plen;
            bip388_dt_t *subs[2] = {0};
            bip388_err_t err = parse_n_subscripts(p, ctx, depth, 2, subs);
            if (err) return err;
            bip388_dt_t *dt = alloc_dt(pairs[i].kind);
            if (!dt) {
                for (int j = 0; j < 2; ++j) { bip388_dt_free(subs[j]); free(subs[j]); }
                return BIP388_ERR_NO_MEMORY;
            }
            dt->u.pair.x = subs[0]; dt->u.pair.y = subs[1];
            *out = dt;
            return BIP388_OK;
        }
    }
    if (p->pos < p->len && p->src[p->pos] == '0') {
        p->pos++;
        bip388_dt_t *dt = alloc_dt(BIP388_DT_ZERO);
        if (!dt) return BIP388_ERR_NO_MEMORY;
        *out = dt;
        return BIP388_OK;
    }
    if (p->pos < p->len && p->src[p->pos] == '1') {
        p->pos++;
        bip388_dt_t *dt = alloc_dt(BIP388_DT_ONE);
        if (!dt) return BIP388_ERR_NO_MEMORY;
        *out = dt;
        return BIP388_OK;
    }
    return BIP388_ERR_UNRECOGNIZED_FRAGMENT;
}

bip388_err_t bip388_dt_from_str(const char *s, bip388_dt_t **out) {
    bip388_parser_t p = { .src = s, .pos = 0, .len = strlen(s) };
    bip388_dt_t *dt = NULL;
    bip388_err_t err = parse_descriptor(&p, BIP388_CTX_TOP_LEVEL, 0, &dt);
    if (err) return err;
    if (p.pos != p.len) {
        bip388_dt_free(dt); free(dt);
        return BIP388_ERR_TRAILING_INPUT;
    }
    *out = dt;
    return BIP388_OK;
}

/* ============================================================ */
/* Equality                                                     */
/* ============================================================ */

static bool tt_equal(const bip388_tap_tree_t *a, const bip388_tap_tree_t *b);

bool bip388_dt_equal(const bip388_dt_t *a, const bip388_dt_t *b) {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a->kind != b->kind) return false;
    switch (a->kind) {
        case BIP388_DT_ZERO:
        case BIP388_DT_ONE:
            return true;
        case BIP388_DT_OLDER:
        case BIP388_DT_AFTER:
            return a->u.num == b->u.num;
        case BIP388_DT_SHA256:
        case BIP388_DT_HASH256:
            return memcmp(a->u.hash, b->u.hash, 32) == 0;
        case BIP388_DT_RIPEMD160:
        case BIP388_DT_HASH160:
            return memcmp(a->u.hash, b->u.hash, 20) == 0;
        case BIP388_DT_SH: case BIP388_DT_WSH:
        case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
        case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
        case BIP388_DT_L: case BIP388_DT_U:
            return bip388_dt_equal(a->u.inner, b->u.inner);
        case BIP388_DT_PKH: case BIP388_DT_WPKH:
        case BIP388_DT_PK:  case BIP388_DT_PK_K: case BIP388_DT_PK_H:
            return bip388_ke_equal(&a->u.key, &b->u.key);
        case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
        case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A:
            if (a->u.multi.threshold != b->u.multi.threshold) return false;
            if (a->u.multi.n_keys != b->u.multi.n_keys) return false;
            for (size_t i = 0; i < a->u.multi.n_keys; ++i)
                if (!bip388_ke_equal(&a->u.multi.keys[i], &b->u.multi.keys[i])) return false;
            return true;
        case BIP388_DT_THRESH:
            if (a->u.thresh.threshold != b->u.thresh.threshold) return false;
            if (a->u.thresh.n_subs != b->u.thresh.n_subs) return false;
            for (size_t i = 0; i < a->u.thresh.n_subs; ++i)
                if (!bip388_dt_equal(a->u.thresh.subs[i], b->u.thresh.subs[i])) return false;
            return true;
        case BIP388_DT_ANDOR:
            return bip388_dt_equal(a->u.trio.x, b->u.trio.x)
                && bip388_dt_equal(a->u.trio.y, b->u.trio.y)
                && bip388_dt_equal(a->u.trio.z, b->u.trio.z);
        case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
        case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I:
            return bip388_dt_equal(a->u.pair.x, b->u.pair.x)
                && bip388_dt_equal(a->u.pair.y, b->u.pair.y);
        case BIP388_DT_TR:
            if (!bip388_ke_equal(&a->u.tr.key, &b->u.tr.key)) return false;
            if (!a->u.tr.tree && !b->u.tr.tree) return true;
            if (!a->u.tr.tree || !b->u.tr.tree) return false;
            return tt_equal(a->u.tr.tree, b->u.tr.tree);
    }
    return false;
}

static bool tt_equal(const bip388_tap_tree_t *a, const bip388_tap_tree_t *b) {
    if (a->kind != b->kind) return false;
    if (a->kind == BIP388_TT_SCRIPT) return bip388_dt_equal(a->u.script, b->u.script);
    return tt_equal(a->u.branch.left, b->u.branch.left)
        && tt_equal(a->u.branch.right, b->u.branch.right);
}

/* ============================================================ */
/* Placeholders iterator (collect into array)                   */
/* ============================================================ */

typedef struct {
    const bip388_dt_t *dt;
    const bip388_dt_t *tapleaf; /* may be NULL */
} frag_stack_entry_t;

typedef struct {
    bip388_placeholder_t *data;
    size_t len;
    size_t cap;
} ph_vec_t;

typedef struct {
    frag_stack_entry_t *data;
    size_t len;
    size_t cap;
} frag_vec_t;

static int ph_push(ph_vec_t *v, bip388_placeholder_t p) {
    if (v->len == v->cap) {
        size_t nc = v->cap ? v->cap * 2 : 16;
        bip388_placeholder_t *np = (bip388_placeholder_t *)realloc(v->data, nc * sizeof(*np));
        if (!np) return -1;
        v->data = np; v->cap = nc;
    }
    v->data[v->len++] = p;
    return 0;
}

static int frag_push(frag_vec_t *v, frag_stack_entry_t e) {
    if (v->len == v->cap) {
        size_t nc = v->cap ? v->cap * 2 : 16;
        frag_stack_entry_t *np = (frag_stack_entry_t *)realloc(v->data, nc * sizeof(*np));
        if (!np) return -1;
        v->data = np; v->cap = nc;
    }
    v->data[v->len++] = e;
    return 0;
}

bip388_err_t bip388_dt_placeholders(const bip388_dt_t *dt,
                                    bip388_placeholder_t **out, size_t *out_n) {
    ph_vec_t result = {0};
    ph_vec_t placeholders = {0}; /* deferred (reverse-pop) buffer */
    frag_vec_t fragments = {0};
    frag_stack_entry_t init = { .dt = dt, .tapleaf = NULL };
    if (frag_push(&fragments, init) < 0) goto oom;

    while (placeholders.len > 0 || fragments.len > 0) {
        if (placeholders.len > 0) {
            bip388_placeholder_t top = placeholders.data[--placeholders.len];
            if (ph_push(&result, top) < 0) goto oom;
            continue;
        }
        frag_stack_entry_t cur = fragments.data[--fragments.len];
        const bip388_dt_t *f = cur.dt;
        const bip388_dt_t *tl = cur.tapleaf;
        switch (f->kind) {
            case BIP388_DT_SH: case BIP388_DT_WSH:
            case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
            case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
            case BIP388_DT_L: case BIP388_DT_U: {
                frag_stack_entry_t e = { .dt = f->u.inner, .tapleaf = tl };
                if (frag_push(&fragments, e) < 0) goto oom;
                break;
            }
            case BIP388_DT_ANDOR: {
                frag_stack_entry_t e3 = { .dt = f->u.trio.z, .tapleaf = tl };
                frag_stack_entry_t e2 = { .dt = f->u.trio.y, .tapleaf = tl };
                frag_stack_entry_t e1 = { .dt = f->u.trio.x, .tapleaf = tl };
                if (frag_push(&fragments, e3) < 0) goto oom;
                if (frag_push(&fragments, e2) < 0) goto oom;
                if (frag_push(&fragments, e1) < 0) goto oom;
                break;
            }
            case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
            case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I: {
                frag_stack_entry_t e2 = { .dt = f->u.pair.y, .tapleaf = tl };
                frag_stack_entry_t e1 = { .dt = f->u.pair.x, .tapleaf = tl };
                if (frag_push(&fragments, e2) < 0) goto oom;
                if (frag_push(&fragments, e1) < 0) goto oom;
                break;
            }
            case BIP388_DT_TR: {
                bip388_placeholder_t ph = { .ke = &f->u.tr.key, .tapleaf = NULL };
                if (ph_push(&placeholders, ph) < 0) goto oom;
                if (f->u.tr.tree) {
                    /* Collect tapleaves in left-to-right order, then reverse. */
                    const bip388_tap_tree_t *stack[256];
                    size_t sp = 0;
                    stack[sp++] = f->u.tr.tree;
                    const bip388_dt_t *leaves[256];
                    size_t n_leaves = 0;
                    while (sp > 0) {
                        const bip388_tap_tree_t *node = stack[--sp];
                        if (node->kind == BIP388_TT_SCRIPT) {
                            leaves[n_leaves++] = node->u.script;
                        } else {
                            stack[sp++] = node->u.branch.right;
                            stack[sp++] = node->u.branch.left;
                        }
                    }
                    /* Push leaves in reverse so they pop in order. */
                    for (size_t i = n_leaves; i > 0; --i) {
                        const bip388_dt_t *leaf = leaves[i - 1];
                        frag_stack_entry_t e = { .dt = leaf, .tapleaf = leaf };
                        if (frag_push(&fragments, e) < 0) goto oom;
                    }
                }
                break;
            }
            case BIP388_DT_PKH: case BIP388_DT_WPKH:
            case BIP388_DT_PK:  case BIP388_DT_PK_K: case BIP388_DT_PK_H: {
                bip388_placeholder_t ph = { .ke = &f->u.key, .tapleaf = tl };
                /* Emit directly (Rust returns Some early). To match Rust, the
                 * Rust code returned early; we emulate by pushing on
                 * `placeholders` so we don't reorder w.r.t. the multi/thresh
                 * traversal. Pushing instead of returning preserves order
                 * here because the placeholders stack is drained at the top
                 * of the loop. */
                if (ph_push(&placeholders, ph) < 0) goto oom;
                break;
            }
            case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
            case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A: {
                for (size_t i = f->u.multi.n_keys; i > 0; --i) {
                    bip388_placeholder_t ph = { .ke = &f->u.multi.keys[i - 1], .tapleaf = tl };
                    if (ph_push(&placeholders, ph) < 0) goto oom;
                }
                break;
            }
            case BIP388_DT_THRESH: {
                for (size_t i = f->u.thresh.n_subs; i > 0; --i) {
                    frag_stack_entry_t e = { .dt = f->u.thresh.subs[i - 1], .tapleaf = tl };
                    if (frag_push(&fragments, e) < 0) goto oom;
                }
                break;
            }
            default:
                break;
        }
    }

    free(fragments.data);
    free(placeholders.data);
    *out = result.data;
    *out_n = result.len;
    return BIP388_OK;

oom:
    free(fragments.data);
    free(placeholders.data);
    free(result.data);
    return BIP388_ERR_NO_MEMORY;
}

void bip388_dt_placeholders_free(bip388_placeholder_t *p) { free(p); }

/* ============================================================ */
/* to_descriptor (concrete key rendering)                       */
/* ============================================================ */

static bip388_err_t fmt_key_info(const bip388_key_info_t *ki, bip388_sbuf_t *b);

static bip388_err_t write_ke(const bip388_ke_t *ke, const bip388_key_info_t *kis,
                             size_t n_kis, bool is_change, uint32_t addr_idx,
                             bip388_sbuf_t *b) {
    uint32_t step = is_change ? ke->num2 : ke->num1;
    if (ke->type == BIP388_KE_PLAIN) {
        if (ke->u.plain_index >= n_kis) return BIP388_ERR_INVALID_KEY_INDEX;
        bip388_err_t err = fmt_key_info(&kis[ke->u.plain_index], b);
        if (err) return err;
        return bip388_sbuf_pushf(b, "/%u/%u", step, addr_idx);
    }
    bip388_err_t err = bip388_sbuf_push(b, BIP388_LIT("musig("));
    if (err) return err;
    for (size_t i = 0; i < ke->u.musig.n_indices; ++i) {
        if (i > 0) {
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
        }
        uint32_t idx = ke->u.musig.indices[i];
        if (idx >= n_kis) return BIP388_ERR_INVALID_KEY_INDEX;
        err = fmt_key_info(&kis[idx], b);
        if (err) return err;
    }
    return bip388_sbuf_pushf(b, ")/%u/%u", step, addr_idx);
}

static bip388_err_t fmt_key_info(const bip388_key_info_t *ki, bip388_sbuf_t *b) {
    bip388_err_t err;
    if (ki->has_origin) {
        err = bip388_sbuf_pushc(b, '[');
        if (err) return err;
        err = bip388_sbuf_pushf(b, "%08x", ki->origin.fingerprint);
        if (err) return err;
        for (size_t i = 0; i < ki->origin.n_path; ++i) {
            uint32_t s = ki->origin.path[i];
            if (s >= BIP388_HARDENED_INDEX) {
                err = bip388_sbuf_pushf(b, "/%u'", s - BIP388_HARDENED_INDEX);
            } else {
                err = bip388_sbuf_pushf(b, "/%u", s);
            }
            if (err) return err;
        }
        err = bip388_sbuf_pushc(b, ']');
        if (err) return err;
    }
    char buf[120];
    size_t n = bip388_xpub_to_str(&ki->xpub, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return BIP388_ERR_FORMAT_ERROR;
    return bip388_sbuf_push(b, buf, n);
}

static bip388_err_t dt_to_descriptor_sbuf(const bip388_dt_t *dt,
                                          const bip388_key_info_t *kis, size_t n_kis,
                                          bool is_change, uint32_t addr_idx,
                                          bip388_sbuf_t *b);

static bip388_err_t tt_to_descriptor_sbuf(const bip388_tap_tree_t *tt,
                                          const bip388_key_info_t *kis, size_t n_kis,
                                          bool is_change, uint32_t addr_idx,
                                          bip388_sbuf_t *b) {
    if (tt->kind == BIP388_TT_SCRIPT)
        return dt_to_descriptor_sbuf(tt->u.script, kis, n_kis, is_change, addr_idx, b);
    bip388_err_t err = bip388_sbuf_pushc(b, '{');
    if (err) return err;
    err = tt_to_descriptor_sbuf(tt->u.branch.left, kis, n_kis, is_change, addr_idx, b);
    if (err) return err;
    err = bip388_sbuf_pushc(b, ',');
    if (err) return err;
    err = tt_to_descriptor_sbuf(tt->u.branch.right, kis, n_kis, is_change, addr_idx, b);
    if (err) return err;
    return bip388_sbuf_pushc(b, '}');
}

static bip388_err_t dt_to_descriptor_sbuf(const bip388_dt_t *dt,
                                          const bip388_key_info_t *kis, size_t n_kis,
                                          bool is_change, uint32_t addr_idx,
                                          bip388_sbuf_t *b) {
    const char *name = bip388_kind_lower(dt->kind);
    bip388_err_t err;
    switch (dt->kind) {
        case BIP388_DT_ZERO: return bip388_sbuf_pushc(b, '0');
        case BIP388_DT_ONE:  return bip388_sbuf_pushc(b, '1');
        case BIP388_DT_OLDER:
        case BIP388_DT_AFTER:
            return bip388_sbuf_pushf(b, "%s(%u)", name, dt->u.num);
        case BIP388_DT_SHA256:
        case BIP388_DT_HASH256:
        case BIP388_DT_RIPEMD160:
        case BIP388_DT_HASH160: {
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            size_t hlen = hash_len_for_kind(dt->kind);
            for (size_t i = 0; i < hlen; ++i) {
                err = bip388_sbuf_pushf(b, "%02x", dt->u.hash[i]);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        }
        case BIP388_DT_PKH: case BIP388_DT_WPKH:
        case BIP388_DT_PK:  case BIP388_DT_PK_K: case BIP388_DT_PK_H:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = write_ke(&dt->u.key, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_SH: case BIP388_DT_WSH:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.inner, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
        case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
        case BIP388_DT_L: case BIP388_DT_U: {
            err = bip388_sbuf_pushc(b, bip388_wrapper_to_char(dt->kind));
            if (err) return err;
            if (!bip388_kind_is_wrapper(dt->u.inner->kind)) {
                err = bip388_sbuf_pushc(b, ':');
                if (err) return err;
            }
            return dt_to_descriptor_sbuf(dt->u.inner, kis, n_kis, is_change, addr_idx, b);
        }
        case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
        case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A:
            err = bip388_sbuf_pushf(b, "%s(%u,", name, dt->u.multi.threshold);
            if (err) return err;
            for (size_t i = 0; i < dt->u.multi.n_keys; ++i) {
                if (i > 0) {
                    err = bip388_sbuf_pushc(b, ',');
                    if (err) return err;
                }
                err = write_ke(&dt->u.multi.keys[i], kis, n_kis, is_change, addr_idx, b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_THRESH:
            err = bip388_sbuf_pushf(b, "thresh(%u", dt->u.thresh.threshold);
            if (err) return err;
            for (size_t i = 0; i < dt->u.thresh.n_subs; ++i) {
                err = bip388_sbuf_pushc(b, ',');
                if (err) return err;
                err = dt_to_descriptor_sbuf(dt->u.thresh.subs[i], kis, n_kis, is_change, addr_idx, b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_ANDOR:
            err = bip388_sbuf_push(b, BIP388_LIT("andor("));
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.trio.x, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.trio.y, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.trio.z, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
        case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I:
            err = bip388_sbuf_pushf(b, "%s(", name);
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.pair.x, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            err = bip388_sbuf_pushc(b, ',');
            if (err) return err;
            err = dt_to_descriptor_sbuf(dt->u.pair.y, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            return bip388_sbuf_pushc(b, ')');
        case BIP388_DT_TR:
            err = bip388_sbuf_push(b, BIP388_LIT("tr("));
            if (err) return err;
            err = write_ke(&dt->u.tr.key, kis, n_kis, is_change, addr_idx, b);
            if (err) return err;
            if (dt->u.tr.tree) {
                err = bip388_sbuf_pushc(b, ',');
                if (err) return err;
                err = tt_to_descriptor_sbuf(dt->u.tr.tree, kis, n_kis, is_change, addr_idx, b);
                if (err) return err;
            }
            return bip388_sbuf_pushc(b, ')');
    }
    return BIP388_ERR_FORMAT_ERROR;
}

bip388_err_t bip388_dt_to_descriptor(const bip388_dt_t *dt,
                                     const bip388_key_info_t *keys, size_t n_keys,
                                     bool is_change, uint32_t address_index,
                                     char *out, size_t cap, size_t *out_len) {
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    bip388_err_t err = dt_to_descriptor_sbuf(dt, keys, n_keys, is_change, address_index, &b);
    if (err) { bip388_sbuf_free(&b); return err; }
    if (out_len) *out_len = b.len;
    if (cap < b.len + 1) { bip388_sbuf_free(&b); return BIP388_ERR_BUFFER_TOO_SMALL; }
    memcpy(out, b.data, b.len);
    out[b.len] = '\0';
    bip388_sbuf_free(&b);
    return BIP388_OK;
}
