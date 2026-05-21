#include "internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *bip388_err_name(bip388_err_t e) {
    switch (e) {
        case BIP388_OK: return "Ok";
        case BIP388_ERR_EMPTY_INPUT: return "EmptyInput";
        case BIP388_ERR_TRAILING_INPUT: return "TrailingInput";
        case BIP388_ERR_INVALID_SYNTAX: return "InvalidSyntax";
        case BIP388_ERR_INVALID_HEX: return "InvalidHex";
        case BIP388_ERR_INVALID_KEY: return "InvalidKey";
        case BIP388_ERR_NUMBER_OUT_OF_RANGE: return "NumberOutOfRange";
        case BIP388_ERR_INVALID_LENGTH: return "InvalidLength";
        case BIP388_ERR_UNRECOGNIZED_FRAGMENT: return "UnrecognizedFragment";
        case BIP388_ERR_TOO_FEW_KEY_EXPRESSIONS: return "TooFewKeyExpressions";
        case BIP388_ERR_THRESH_EXCEEDS_SCRIPTS: return "ThreshExceedsScripts";
        case BIP388_ERR_INVALID_KEY_INDEX: return "InvalidKeyIndex";
        case BIP388_ERR_INVALID_TOP_LEVEL_POLICY: return "InvalidTopLevelPolicy";
        case BIP388_ERR_FORMAT_ERROR: return "FormatError";
        case BIP388_ERR_INVALID_SCRIPT_CONTEXT: return "InvalidScriptContext";
        case BIP388_ERR_TOO_MANY_KEYS: return "TooManyKeys";
        case BIP388_ERR_INVALID_MULTISIG_QUORUM: return "InvalidMultisigQuorum";
        case BIP388_ERR_NESTING_TOO_DEEP: return "NestingTooDeep";
        case BIP388_ERR_NO_MEMORY: return "NoMemory";
        case BIP388_ERR_BUFFER_TOO_SMALL: return "BufferTooSmall";
        case BIP388_ERR_DESERIALIZE: return "Deserialize";
    }
    return "?";
}

const char *bip388_kind_lower(bip388_dt_kind_t k) {
    switch (k) {
        case BIP388_DT_ZERO: return "0";
        case BIP388_DT_ONE: return "1";
        case BIP388_DT_SH: return "sh";
        case BIP388_DT_WSH: return "wsh";
        case BIP388_DT_PKH: return "pkh";
        case BIP388_DT_WPKH: return "wpkh";
        case BIP388_DT_PK: return "pk";
        case BIP388_DT_PK_K: return "pk_k";
        case BIP388_DT_PK_H: return "pk_h";
        case BIP388_DT_OLDER: return "older";
        case BIP388_DT_AFTER: return "after";
        case BIP388_DT_MULTI: return "multi";
        case BIP388_DT_MULTI_A: return "multi_a";
        case BIP388_DT_SORTEDMULTI: return "sortedmulti";
        case BIP388_DT_SORTEDMULTI_A: return "sortedmulti_a";
        case BIP388_DT_TR: return "tr";
        case BIP388_DT_SHA256: return "sha256";
        case BIP388_DT_HASH256: return "hash256";
        case BIP388_DT_RIPEMD160: return "ripemd160";
        case BIP388_DT_HASH160: return "hash160";
        case BIP388_DT_ANDOR: return "andor";
        case BIP388_DT_AND_V: return "and_v";
        case BIP388_DT_AND_B: return "and_b";
        case BIP388_DT_AND_N: return "and_n";
        case BIP388_DT_OR_B: return "or_b";
        case BIP388_DT_OR_C: return "or_c";
        case BIP388_DT_OR_D: return "or_d";
        case BIP388_DT_OR_I: return "or_i";
        case BIP388_DT_THRESH: return "thresh";
        case BIP388_DT_A: return "a";
        case BIP388_DT_S: return "s";
        case BIP388_DT_C: return "c";
        case BIP388_DT_T: return "t";
        case BIP388_DT_D: return "d";
        case BIP388_DT_V: return "v";
        case BIP388_DT_J: return "j";
        case BIP388_DT_N: return "n";
        case BIP388_DT_L: return "l";
        case BIP388_DT_U: return "u";
    }
    return NULL;
}

bool bip388_wrapper_from_char(char c, bip388_dt_kind_t *out) {
    switch (c) {
        case 'a': *out = BIP388_DT_A; return true;
        case 's': *out = BIP388_DT_S; return true;
        case 'c': *out = BIP388_DT_C; return true;
        case 't': *out = BIP388_DT_T; return true;
        case 'd': *out = BIP388_DT_D; return true;
        case 'v': *out = BIP388_DT_V; return true;
        case 'j': *out = BIP388_DT_J; return true;
        case 'n': *out = BIP388_DT_N; return true;
        case 'l': *out = BIP388_DT_L; return true;
        case 'u': *out = BIP388_DT_U; return true;
    }
    return false;
}

char bip388_wrapper_to_char(bip388_dt_kind_t k) {
    switch (k) {
        case BIP388_DT_A: return 'a';
        case BIP388_DT_S: return 's';
        case BIP388_DT_C: return 'c';
        case BIP388_DT_T: return 't';
        case BIP388_DT_D: return 'd';
        case BIP388_DT_V: return 'v';
        case BIP388_DT_J: return 'j';
        case BIP388_DT_N: return 'n';
        case BIP388_DT_L: return 'l';
        case BIP388_DT_U: return 'u';
        default: return 0;
    }
}

bool bip388_kind_is_wrapper(bip388_dt_kind_t k) {
    return bip388_wrapper_to_char(k) != 0;
}

/* sbuf */

bip388_err_t bip388_sbuf_init(bip388_sbuf_t *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    return BIP388_OK;
}

void bip388_sbuf_free(bip388_sbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static bip388_err_t sbuf_reserve(bip388_sbuf_t *b, size_t extra) {
    /* Always keep room for trailing NUL. */
    size_t need = b->len + extra + 1;
    if (need <= b->cap) return BIP388_OK;
    size_t new_cap = b->cap ? b->cap : 32;
    while (new_cap < need) new_cap *= 2;
    char *p = (char *)realloc(b->data, new_cap);
    if (!p) return BIP388_ERR_NO_MEMORY;
    b->data = p;
    b->cap = new_cap;
    return BIP388_OK;
}

bip388_err_t bip388_sbuf_push(bip388_sbuf_t *b, const char *s, size_t n) {
    bip388_err_t err = sbuf_reserve(b, n);
    if (err != BIP388_OK) return err;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return BIP388_OK;
}

bip388_err_t bip388_sbuf_pushc(bip388_sbuf_t *b, char c) {
    return bip388_sbuf_push(b, &c, 1);
}

bip388_err_t bip388_sbuf_pushf(bip388_sbuf_t *b, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return BIP388_ERR_FORMAT_ERROR;
    }
    bip388_err_t err = sbuf_reserve(b, (size_t)n);
    if (err != BIP388_OK) {
        va_end(ap2);
        return err;
    }
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return BIP388_OK;
}

void bip388_free_buf(void *p) { free(p); }
