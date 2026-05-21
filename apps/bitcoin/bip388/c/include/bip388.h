/* BIP-388 wallet policies & descriptor templates — C port.
 *
 * Mirrors the Rust `bip388` crate without the `cleartext-decode`
 * feature. The descriptor template AST is represented as a tagged
 * union (`bip388_dt_t`); allocations are owned and must be released
 * with the matching `_free` function.
 */
#ifndef BIP388_H
#define BIP388_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define BIP388_HARDENED_INDEX                       0x80000000u
#define BIP388_MAX_OLDER_AFTER                      2147483647u
#define BIP388_MAX_KEYS_MULTI                       20u
#define BIP388_MAX_KEYS_MULTI_A                     999u
#define BIP388_MAX_PARSE_DEPTH                      64u
#define BIP388_MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN 4096u
#define BIP388_MAX_SERIALIZED_KEY_COUNT             BIP388_MAX_KEYS_MULTI_A
#define BIP388_MAX_BIP32_DERIVATION_PATH_LEN        32u
#define BIP388_MAX_CONFUSION_SCORE                  3600u
#define BIP388_SEQUENCE_LOCKTIME_TYPE_FLAG          (1u << 22)

/* ------------------------------------------------------------------ */
/* Error codes                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    BIP388_OK = 0,
    BIP388_ERR_EMPTY_INPUT,
    BIP388_ERR_TRAILING_INPUT,
    BIP388_ERR_INVALID_SYNTAX,
    BIP388_ERR_INVALID_HEX,
    BIP388_ERR_INVALID_KEY,
    BIP388_ERR_NUMBER_OUT_OF_RANGE,
    BIP388_ERR_INVALID_LENGTH,
    BIP388_ERR_UNRECOGNIZED_FRAGMENT,
    BIP388_ERR_TOO_FEW_KEY_EXPRESSIONS,
    BIP388_ERR_THRESH_EXCEEDS_SCRIPTS,
    BIP388_ERR_INVALID_KEY_INDEX,
    BIP388_ERR_INVALID_TOP_LEVEL_POLICY,
    BIP388_ERR_FORMAT_ERROR,
    BIP388_ERR_INVALID_SCRIPT_CONTEXT,
    BIP388_ERR_TOO_MANY_KEYS,
    BIP388_ERR_INVALID_MULTISIG_QUORUM,
    BIP388_ERR_NESTING_TOO_DEEP,
    BIP388_ERR_NO_MEMORY,
    BIP388_ERR_BUFFER_TOO_SMALL,
    BIP388_ERR_DESERIALIZE,
} bip388_err_t;

const char *bip388_err_name(bip388_err_t e);

/* ------------------------------------------------------------------ */
/* Xpub (78-byte BIP-32 serialization)                                */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t raw[78];
} bip388_xpub_t;

bip388_err_t bip388_xpub_from_str(const char *s, size_t len, bip388_xpub_t *out);
/* Writes a NUL-terminated base58check string. Returns total length
 * (excluding NUL) on success; if `cap` is too small, returns the
 * required size and the buffer is left undefined. */
size_t bip388_xpub_to_str(const bip388_xpub_t *x, char *out, size_t cap);

/* ------------------------------------------------------------------ */
/* Key origin / key information                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t fingerprint;
    uint32_t *path; /* owned, may be NULL when n_path == 0 */
    size_t n_path;
} bip388_key_origin_t;

void bip388_key_origin_free(bip388_key_origin_t *o);
bip388_err_t bip388_key_origin_parse(const char *s, size_t len, bip388_key_origin_t *out);
size_t bip388_key_origin_format(const bip388_key_origin_t *o, char *out, size_t cap);

typedef struct {
    bip388_xpub_t xpub;
    bool has_origin;
    bip388_key_origin_t origin; /* valid iff has_origin */
} bip388_key_info_t;

void bip388_key_info_free(bip388_key_info_t *ki);
bip388_err_t bip388_key_info_parse(const char *s, bip388_key_info_t *out);
size_t bip388_key_info_format(const bip388_key_info_t *ki, char *out, size_t cap);

/* ------------------------------------------------------------------ */
/* Key expression                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    BIP388_KE_PLAIN,
    BIP388_KE_MUSIG,
} bip388_ke_type_t;

typedef struct {
    bip388_ke_type_t type;
    uint32_t num1;
    uint32_t num2;
    union {
        uint32_t plain_index;
        struct {
            uint32_t *indices; /* owned */
            size_t n_indices;
        } musig;
    } u;
} bip388_ke_t;

void bip388_ke_init_plain(bip388_ke_t *ke, uint32_t idx, uint32_t n1, uint32_t n2);
bip388_err_t bip388_ke_init_musig(bip388_ke_t *ke, const uint32_t *idx, size_t n, uint32_t n1, uint32_t n2);
void bip388_ke_free(bip388_ke_t *ke);
bool bip388_ke_equal(const bip388_ke_t *a, const bip388_ke_t *b);
size_t bip388_ke_format(const bip388_ke_t *ke, char *out, size_t cap);

/* ------------------------------------------------------------------ */
/* DescriptorTemplate + TapTree                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    BIP388_DT_ZERO,
    BIP388_DT_ONE,
    BIP388_DT_SH,
    BIP388_DT_WSH,
    BIP388_DT_PKH,
    BIP388_DT_WPKH,
    BIP388_DT_PK,
    BIP388_DT_PK_K,
    BIP388_DT_PK_H,
    BIP388_DT_OLDER,
    BIP388_DT_AFTER,
    BIP388_DT_MULTI,
    BIP388_DT_MULTI_A,
    BIP388_DT_SORTEDMULTI,
    BIP388_DT_SORTEDMULTI_A,
    BIP388_DT_TR,
    BIP388_DT_SHA256,
    BIP388_DT_HASH256,
    BIP388_DT_RIPEMD160,
    BIP388_DT_HASH160,
    BIP388_DT_ANDOR,
    BIP388_DT_AND_V,
    BIP388_DT_AND_B,
    BIP388_DT_AND_N,
    BIP388_DT_OR_B,
    BIP388_DT_OR_C,
    BIP388_DT_OR_D,
    BIP388_DT_OR_I,
    BIP388_DT_THRESH,
    /* wrappers */
    BIP388_DT_A, BIP388_DT_S, BIP388_DT_C, BIP388_DT_T, BIP388_DT_D,
    BIP388_DT_V, BIP388_DT_J, BIP388_DT_N, BIP388_DT_L, BIP388_DT_U,
} bip388_dt_kind_t;

typedef struct bip388_dt bip388_dt_t;
typedef struct bip388_tap_tree bip388_tap_tree_t;

typedef enum { BIP388_TT_SCRIPT, BIP388_TT_BRANCH } bip388_tt_kind_t;

struct bip388_tap_tree {
    bip388_tt_kind_t kind;
    union {
        bip388_dt_t *script; /* owned */
        struct {
            bip388_tap_tree_t *left;  /* owned */
            bip388_tap_tree_t *right; /* owned */
        } branch;
    } u;
};

struct bip388_dt {
    bip388_dt_kind_t kind;
    union {
        bip388_dt_t *inner;            /* Sh, Wsh, wrappers */
        bip388_ke_t key;               /* Pkh, Wpkh, Pk, Pk_k, Pk_h */
        uint32_t num;                  /* Older, After */
        uint8_t hash[32];              /* Sha256/Hash256 use 32 bytes; Ripemd160/Hash160 use first 20 */
        struct {
            uint32_t threshold;
            bip388_ke_t *keys;
            size_t n_keys;
        } multi;
        struct {
            uint32_t threshold;
            bip388_dt_t **subs;
            size_t n_subs;
        } thresh;
        struct { bip388_dt_t *x, *y, *z; } trio;
        struct { bip388_dt_t *x, *y; } pair;
        struct {
            bip388_ke_t key;
            bip388_tap_tree_t *tree; /* nullable */
        } tr;
    } u;
};

void bip388_dt_free(bip388_dt_t *dt);
void bip388_tt_free(bip388_tap_tree_t *tt);

bip388_err_t bip388_dt_from_str(const char *s, bip388_dt_t **out);
/* Returns required length (excluding NUL) on success. */
size_t bip388_dt_format(const bip388_dt_t *dt, char *out, size_t cap);
size_t bip388_tt_format(const bip388_tap_tree_t *tt, char *out, size_t cap);

bool bip388_dt_equal(const bip388_dt_t *a, const bip388_dt_t *b);

/* Render with concrete key information. */
bip388_err_t bip388_dt_to_descriptor(const bip388_dt_t *dt,
                                     const bip388_key_info_t *keys, size_t n_keys,
                                     bool is_change, uint32_t address_index,
                                     char *out, size_t cap, size_t *out_len);

/* Placeholders iteration: collect all (KeyExpression, tapleaf_or_null) pairs
 * in traversal order. Caller frees `*pairs` with bip388_dt_placeholders_free. */
typedef struct {
    const bip388_ke_t *ke;
    const bip388_dt_t *tapleaf; /* may be NULL */
} bip388_placeholder_t;

bip388_err_t bip388_dt_placeholders(const bip388_dt_t *dt,
                                    bip388_placeholder_t **out, size_t *out_n);
void bip388_dt_placeholders_free(bip388_placeholder_t *p);

/* ------------------------------------------------------------------ */
/* WalletPolicy                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    BIP388_SW_LEGACY,
    BIP388_SW_SEGWIT_V0,
    BIP388_SW_TAPROOT,
} bip388_segwit_t;

typedef struct {
    bip388_dt_t *descriptor_template;          /* owned */
    char *descriptor_template_raw;             /* owned, NUL-terminated */
    bip388_key_info_t *key_information;        /* owned */
    size_t n_key_information;
} bip388_wallet_policy_t;

bip388_err_t bip388_wp_new(const char *desc_template,
                           const bip388_key_info_t *keys, size_t n_keys,
                           bip388_wallet_policy_t *out);
void bip388_wp_free(bip388_wallet_policy_t *wp);

bip388_err_t bip388_wp_segwit_version(const bip388_wallet_policy_t *wp, bip388_segwit_t *out);

/* Returns a heap buffer (caller frees with bip388_free_buf). */
bip388_err_t bip388_wp_serialize(const bip388_wallet_policy_t *wp,
                                 uint8_t **out, size_t *out_len);
bip388_err_t bip388_wp_deserialize(const uint8_t *data, size_t len,
                                   bip388_wallet_policy_t *out);

void bip388_free_buf(void *p);

/* ------------------------------------------------------------------ */
/* Time formatting (forward direction only)                           */
/* ------------------------------------------------------------------ */

size_t bip388_format_utc_date(uint32_t timestamp, char *out, size_t cap);
size_t bip388_format_seconds(uint32_t secs, char *out, size_t cap);

/* ------------------------------------------------------------------ */
/* Cleartext                                                          */
/* ------------------------------------------------------------------ */

/* Returns the confusion-score upper bound (saturates at UINT64_MAX). */
uint64_t bip388_confusion_score(const bip388_dt_t *dt);

/* Render the cleartext description.
 * `*out_lines` is an array of heap-allocated NUL-terminated strings.
 * Free each entry with `bip388_free_buf`, then the array itself.
 * `*has_cleartext` is true iff every part was recognised.
 */
bip388_err_t bip388_to_cleartext(const bip388_dt_t *dt,
                                 char ***out_lines, size_t *out_n,
                                 bool *has_cleartext);
void bip388_cleartext_free(char **lines, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* BIP388_H */
