/* Internal types and tables used by the cleartext module.
 *
 * Most of this file is consumed by `cleartext.c`; the table contents
 * are emitted from `cleartext.toml` by `tools/gen.py`.
 */
#ifndef BIP388_CLEARTEXT_GEN_H
#define BIP388_CLEARTEXT_GEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../include/bip388.h"

typedef enum {
    BK_NONE = 0,
    BK_KEY,
    BK_KEYLIST,
    BK_THRESHOLD,
    BK_BLOCKS,
    BK_RELATIVE_TIME,
    BK_BLOCK_HEIGHT,
    BK_TIMESTAMP,
    BK_LEAVES,
} bip388_binding_kind_t;

/* Pattern arg AST */

typedef enum {
    PA_BINDING,
    PA_MUSIG,
    PA_SUB,
} bip388_pat_arg_kind_t;

struct bip388_pattern;

typedef struct bip388_pat_arg {
    bip388_pat_arg_kind_t kind;
    /* binding: field_idx + bkind
     * musig: t_field_idx (= field_idx of threshold), k_field_idx (= keys)
     * sub: wrappers + n_wrappers + inner pointer */
    uint8_t field_idx;
    uint8_t field_idx2;
    bip388_binding_kind_t bkind;
    const bip388_dt_kind_t *wrappers;
    uint8_t n_wrappers;
    const struct bip388_pattern *inner;
} bip388_pat_arg_t;

typedef struct bip388_pattern {
    bip388_dt_kind_t variant;
    const bip388_pat_arg_t *args;
    uint8_t n_args;
    bool uses_musig;
} bip388_pattern_t;

/* Cleartext template */

typedef enum { CT_LITERAL, CT_FIELD } bip388_ct_token_kind_t;

typedef struct {
    bip388_ct_token_kind_t kind;
    const char *literal; /* CT_LITERAL */
    uint8_t field_idx;   /* CT_FIELD */
    bip388_binding_kind_t bkind; /* CT_FIELD */
} bip388_ct_token_t;

/* Spec field metadata */

typedef struct {
    const char *name;
    bip388_binding_kind_t kind;
} bip388_spec_field_t;

/* A single spec entry (one [[top_level]] or [[tapleaf]]). */
typedef struct {
    const char *name;
    /* Each pointer references a static-const pattern struct emitted by
     * the codegen. Using an array of pointers (rather than an inline
     * array of values) keeps the initializers ISO-C constant-expressions
     * even when patterns share sub-patterns. */
    const bip388_pattern_t *const *patterns;
    uint8_t n_patterns;
    const bip388_spec_field_t *fields;
    uint8_t n_fields;
    const bip388_ct_token_t *cleartext;
    uint8_t n_cleartext;
    bool recurses;
    uint8_t plain_pattern_count;
    uint8_t musig_pattern_count;
} bip388_spec_entry_t;

extern const bip388_spec_entry_t bip388_top_level_specs[];
extern const size_t bip388_top_level_specs_count;
extern const bip388_spec_entry_t bip388_tapleaf_specs[];
extern const size_t bip388_tapleaf_specs_count;

/* Implicit numeric ranges (inclusive_lo, exclusive_hi). hi == 0 means open-ended. */
void bip388_binding_range(bip388_binding_kind_t k, uint32_t *lo, uint32_t *hi);

#endif /* BIP388_CLEARTEXT_GEN_H */
