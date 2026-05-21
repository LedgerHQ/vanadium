/* Internal helpers shared across bip388 C implementation files. */
#ifndef BIP388_INTERNAL_H
#define BIP388_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/bip388.h"

/* Parser cursor over a non-NUL-terminated slice. */
typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} bip388_parser_t;

static inline bool bip388_p_at_end(const bip388_parser_t *p) {
    return p->pos >= p->len;
}

static inline bool bip388_p_starts_with(const bip388_parser_t *p, const char *needle, size_t nlen) {
    if (p->pos + nlen > p->len) return false;
    for (size_t i = 0; i < nlen; ++i) {
        if (p->src[p->pos + i] != needle[i]) return false;
    }
    return true;
}

#define BIP388_LIT(s) (s), (sizeof(s) - 1)

/* Bump and return true if next byte is `c`. */
static inline bool bip388_p_try(bip388_parser_t *p, char c) {
    if (p->pos < p->len && p->src[p->pos] == c) {
        p->pos++;
        return true;
    }
    return false;
}

typedef enum {
    BIP388_CTX_TOP_LEVEL,
    BIP388_CTX_LEGACY,
    BIP388_CTX_SEGWIT,
    BIP388_CTX_WRAPPED_SEGWIT,
    BIP388_CTX_TAPROOT,
} bip388_ctx_t;

static inline bool bip388_ctx_musig_allowed(bip388_ctx_t c) { return c == BIP388_CTX_TAPROOT; }
static inline bool bip388_ctx_sh_allowed(bip388_ctx_t c) { return c == BIP388_CTX_TOP_LEVEL; }
static inline bool bip388_ctx_wpkh_allowed(bip388_ctx_t c) {
    return c == BIP388_CTX_TOP_LEVEL || c == BIP388_CTX_LEGACY;
}
static inline bool bip388_ctx_wsh_allowed(bip388_ctx_t c) {
    return c == BIP388_CTX_TOP_LEVEL || c == BIP388_CTX_LEGACY;
}
static inline bool bip388_ctx_tr_allowed(bip388_ctx_t c) { return c == BIP388_CTX_TOP_LEVEL; }

/* Display variant tag → lower-case name (used by both Display and
 * to_descriptor). NULL if there is no textual form. */
const char *bip388_kind_lower(bip388_dt_kind_t k);

/* Wrapper char ↔ variant. */
bool bip388_wrapper_from_char(char c, bip388_dt_kind_t *out);
char bip388_wrapper_to_char(bip388_dt_kind_t k); /* 0 if not a wrapper */
bool bip388_kind_is_wrapper(bip388_dt_kind_t k);

/* Owned-bytes buffer helpers used during formatting. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} bip388_sbuf_t;

bip388_err_t bip388_sbuf_init(bip388_sbuf_t *b);
void bip388_sbuf_free(bip388_sbuf_t *b);
bip388_err_t bip388_sbuf_push(bip388_sbuf_t *b, const char *s, size_t n);
bip388_err_t bip388_sbuf_pushf(bip388_sbuf_t *b, const char *fmt, ...);
bip388_err_t bip388_sbuf_pushc(bip388_sbuf_t *b, char c);

/* Saturating multiply for confusion scores. */
static inline uint64_t bip388_sat_mul(uint64_t a, uint64_t b) {
    if (a == 0 || b == 0) return 0;
    if (a > UINT64_MAX / b) return UINT64_MAX;
    return a * b;
}

#endif /* BIP388_INTERNAL_H */
