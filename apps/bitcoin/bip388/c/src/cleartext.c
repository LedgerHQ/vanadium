/* Cleartext classification, confusion score, and rendering.
 *
 * Walks the spec tables emitted from `cleartext.toml` (see
 * `tools/gen.py`) against the descriptor AST. Forward direction only
 * — `cleartext-decode` is not part of this port.
 */

#include "../include/bip388.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cleartext_internal.h"
#include "gen/cleartext_gen.h"
#include "internal.h"

/* The class_instance / field_value types live in `cleartext_internal.h`
 * so tests can inspect classification output without going through the
 * higher-level `to_cleartext` rendering path. */

static void field_value_free(bip388_field_value_t *v) {
    if (v->kind == BK_KEYLIST && v->keylist.owned) {
        for (size_t i = 0; i < v->keylist.n; ++i) bip388_ke_free(&v->keylist.items[i]);
        free(v->keylist.items);
    }
    /* Leaves are owned: free recursively. */
    if (v->kind == BK_LEAVES) {
        /* handled by class_instance_free of parent (which knows leaves array
         * was stored here). */
    }
}

#define class_instance_free bip388_class_instance_free

void bip388_class_instance_free(bip388_class_instance_t *c) {
    if (!c) return;
    if (c->entry) {
        for (size_t i = 0; i < c->entry->n_fields; ++i) {
            bip388_field_value_t *v = &c->fields[i];
            if (v->kind == BK_LEAVES) {
                for (size_t j = 0; j < v->leaves.n; ++j)
                    class_instance_free(&v->leaves.items[j]);
                free(v->leaves.items);
                v->leaves.items = NULL;
            } else {
                field_value_free(v);
            }
        }
        free(c->fields);
        c->fields = NULL;
    }
    free(c->other_str);
    c->other_str = NULL;
}

/* ============================================================ */
/* Pattern matcher                                              */
/* ============================================================ */

#define classify_top_level bip388_classify_internal
#define classify_tapleaf bip388_classify_as_tapleaf_internal

bip388_err_t bip388_classify_internal(const bip388_dt_t *dt, bip388_class_instance_t *out);
bip388_err_t bip388_classify_as_tapleaf_internal(const bip388_dt_t *dt, bip388_class_instance_t *out);

static bool match_arg(const bip388_pat_arg_t *parg, const bip388_dt_t *dt_parent,
                      size_t arg_idx, bip388_field_value_t *bindings);
static bool match_pattern(const bip388_pattern_t *pat, const bip388_dt_t *dt,
                          bip388_field_value_t *bindings);

/* Get the i-th positional arg of `dt`. Returns NULL slot info if missing.
 * For 'Key' arg → bip388_ke_t *; 'Num' → uint32_t; 'KeyList' → list +
 * length; 'Sub' → bip388_dt_t *; 'Tree' → bip388_tap_tree_t* (or NULL). */
typedef enum { AK_KEY, AK_NUM, AK_KEYLIST, AK_SUB, AK_TREE } ak_t;

typedef struct {
    ak_t kind;
    const bip388_ke_t *key;
    uint32_t num;
    const bip388_ke_t *keys; size_t n_keys;
    const bip388_dt_t *sub;
    const bip388_tap_tree_t *tree;
} dt_arg_t;

static bool get_dt_arg(const bip388_dt_t *dt, size_t idx, dt_arg_t *out) {
    memset(out, 0, sizeof(*out));
    switch (dt->kind) {
        case BIP388_DT_PKH: case BIP388_DT_WPKH:
        case BIP388_DT_PK: case BIP388_DT_PK_K: case BIP388_DT_PK_H:
            if (idx != 0) return false;
            out->kind = AK_KEY; out->key = &dt->u.key; return true;
        case BIP388_DT_OLDER: case BIP388_DT_AFTER:
            if (idx != 0) return false;
            out->kind = AK_NUM; out->num = dt->u.num; return true;
        case BIP388_DT_MULTI: case BIP388_DT_MULTI_A:
        case BIP388_DT_SORTEDMULTI: case BIP388_DT_SORTEDMULTI_A:
            if (idx == 0) { out->kind = AK_NUM; out->num = dt->u.multi.threshold; return true; }
            if (idx == 1) {
                out->kind = AK_KEYLIST;
                out->keys = dt->u.multi.keys;
                out->n_keys = dt->u.multi.n_keys;
                return true;
            }
            return false;
        case BIP388_DT_SH: case BIP388_DT_WSH:
        case BIP388_DT_A: case BIP388_DT_S: case BIP388_DT_C: case BIP388_DT_T:
        case BIP388_DT_D: case BIP388_DT_V: case BIP388_DT_J: case BIP388_DT_N:
        case BIP388_DT_L: case BIP388_DT_U:
            if (idx != 0) return false;
            out->kind = AK_SUB; out->sub = dt->u.inner; return true;
        case BIP388_DT_ANDOR:
            out->kind = AK_SUB;
            if (idx == 0) { out->sub = dt->u.trio.x; return true; }
            if (idx == 1) { out->sub = dt->u.trio.y; return true; }
            if (idx == 2) { out->sub = dt->u.trio.z; return true; }
            return false;
        case BIP388_DT_AND_V: case BIP388_DT_AND_B: case BIP388_DT_AND_N:
        case BIP388_DT_OR_B: case BIP388_DT_OR_C: case BIP388_DT_OR_D: case BIP388_DT_OR_I:
            out->kind = AK_SUB;
            if (idx == 0) { out->sub = dt->u.pair.x; return true; }
            if (idx == 1) { out->sub = dt->u.pair.y; return true; }
            return false;
        case BIP388_DT_TR:
            if (idx == 0) { out->kind = AK_KEY; out->key = &dt->u.tr.key; return true; }
            if (idx == 1) { out->kind = AK_TREE; out->tree = dt->u.tr.tree; return true; }
            return false;
        default:
            return false;
    }
}

static bool match_arg(const bip388_pat_arg_t *parg, const bip388_dt_t *dt_parent,
                      size_t arg_idx, bip388_field_value_t *bindings) {
    dt_arg_t a;
    if (!get_dt_arg(dt_parent, arg_idx, &a)) return false;
    if (parg->kind == PA_BINDING) {
        if (parg->bkind == BK_KEY) {
            if (a.kind != AK_KEY || !a.key) return false;
            if (a.key->type != BIP388_KE_PLAIN) return false;
            bindings[parg->field_idx].kind = BK_KEY;
            bindings[parg->field_idx].key = a.key;
            return true;
        }
        if (parg->bkind == BK_KEYLIST) {
            if (a.kind != AK_KEYLIST) return false;
            for (size_t i = 0; i < a.n_keys; ++i)
                if (a.keys[i].type != BIP388_KE_PLAIN) return false;
            bindings[parg->field_idx].kind = BK_KEYLIST;
            bindings[parg->field_idx].keylist.items = (bip388_ke_t *)a.keys;
            bindings[parg->field_idx].keylist.n = a.n_keys;
            bindings[parg->field_idx].keylist.owned = false;
            return true;
        }
        if (parg->bkind == BK_LEAVES) {
            if (a.kind != AK_TREE) return false;
            /* Collect tapleaves and classify each. */
            size_t n_leaves = 0;
            const bip388_dt_t *leaves[256];
            if (a.tree) {
                const bip388_tap_tree_t *stack[256];
                size_t sp = 0;
                stack[sp++] = a.tree;
                while (sp > 0) {
                    const bip388_tap_tree_t *node = stack[--sp];
                    if (node->kind == BIP388_TT_SCRIPT) {
                        leaves[n_leaves++] = node->u.script;
                    } else {
                        stack[sp++] = node->u.branch.right;
                        stack[sp++] = node->u.branch.left;
                    }
                }
            }
            bip388_class_instance_t *items = NULL;
            if (n_leaves) {
                items = (bip388_class_instance_t *)calloc(n_leaves, sizeof(*items));
                if (!items) return false;
            }
            for (size_t i = 0; i < n_leaves; ++i) {
                if (classify_tapleaf(leaves[i], &items[i]) != BIP388_OK) {
                    for (size_t j = 0; j <= i; ++j) class_instance_free(&items[j]);
                    free(items);
                    return false;
                }
            }
            bindings[parg->field_idx].kind = BK_LEAVES;
            bindings[parg->field_idx].leaves.items = items;
            bindings[parg->field_idx].leaves.n = n_leaves;
            return true;
        }
        /* Num kind */
        if (a.kind != AK_NUM) return false;
        uint32_t lo, hi;
        bip388_binding_range(parg->bkind, &lo, &hi);
        if (lo != 0 && a.num < lo) return false;
        if (hi != 0 && a.num >= hi) return false;
        bindings[parg->field_idx].kind = parg->bkind;
        bindings[parg->field_idx].num = a.num;
        return true;
    }
    if (parg->kind == PA_MUSIG) {
        if (a.kind != AK_KEY || !a.key) return false;
        if (a.key->type != BIP388_KE_MUSIG) return false;
        size_t n = a.key->u.musig.n_indices;
        bip388_ke_t *plain = (bip388_ke_t *)calloc(n, sizeof(*plain));
        if (!plain) return false;
        for (size_t i = 0; i < n; ++i) {
            bip388_ke_init_plain(&plain[i], a.key->u.musig.indices[i], a.key->num1, a.key->num2);
        }
        /* threshold */
        bindings[parg->field_idx].kind = BK_THRESHOLD;
        bindings[parg->field_idx].num = (uint32_t)n;
        /* keys list (owned) */
        bindings[parg->field_idx2].kind = BK_KEYLIST;
        bindings[parg->field_idx2].keylist.items = plain;
        bindings[parg->field_idx2].keylist.n = n;
        bindings[parg->field_idx2].keylist.owned = true;
        return true;
    }
    /* PA_SUB */
    if (a.kind != AK_SUB) return false;
    const bip388_dt_t *cur = a.sub;
    for (uint8_t i = 0; i < parg->n_wrappers; ++i) {
        if (cur->kind != parg->wrappers[i]) return false;
        cur = cur->u.inner;
    }
    return match_pattern(parg->inner, cur, bindings);
}

static bool match_pattern(const bip388_pattern_t *pat, const bip388_dt_t *dt,
                          bip388_field_value_t *bindings) {
    if (dt->kind != pat->variant) return false;
    for (uint8_t i = 0; i < pat->n_args; ++i) {
        if (!match_arg(&pat->args[i], dt, i, bindings)) return false;
    }
    return true;
}

/* Try matching one entry against dt. On success, the class instance's
 * `fields` is populated from the first matching pattern's bindings. */
static bip388_err_t try_classify_entry(const bip388_spec_entry_t *entry,
                                       const bip388_dt_t *dt,
                                       bip388_class_instance_t *out,
                                       bool *matched) {
    *matched = false;
    for (uint8_t pi = 0; pi < entry->n_patterns; ++pi) {
        bip388_field_value_t *bindings = NULL;
        if (entry->n_fields) {
            bindings = (bip388_field_value_t *)calloc(entry->n_fields, sizeof(*bindings));
            if (!bindings) return BIP388_ERR_NO_MEMORY;
        }
        if (match_pattern(entry->patterns[pi], dt, bindings)) {
            out->entry = entry;
            out->other_str = NULL;
            out->fields = bindings;
            *matched = true;
            return BIP388_OK;
        }
        /* free any partial allocations done by the failed match */
        if (bindings) {
            for (size_t i = 0; i < entry->n_fields; ++i) {
                bip388_field_value_t *v = &bindings[i];
                if (v->kind == BK_LEAVES) {
                    for (size_t j = 0; j < v->leaves.n; ++j) class_instance_free(&v->leaves.items[j]);
                    free(v->leaves.items);
                } else {
                    field_value_free(v);
                }
            }
            free(bindings);
        }
    }
    return BIP388_OK;
}

bip388_err_t bip388_classify_internal(const bip388_dt_t *dt, bip388_class_instance_t *out) {
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < bip388_top_level_specs_count; ++i) {
        bool matched;
        bip388_err_t err = try_classify_entry(&bip388_top_level_specs[i], dt, out, &matched);
        if (err) return err;
        if (matched) return BIP388_OK;
    }
    out->entry = NULL;
    return BIP388_OK;
}

bip388_err_t bip388_classify_as_tapleaf_internal(const bip388_dt_t *dt, bip388_class_instance_t *out) {
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < bip388_tapleaf_specs_count; ++i) {
        bool matched;
        bip388_err_t err = try_classify_entry(&bip388_tapleaf_specs[i], dt, out, &matched);
        if (err) return err;
        if (matched) return BIP388_OK;
    }
    /* Other: store the rendered descriptor string. */
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    char tmp[16];
    size_t n = bip388_dt_format(dt, tmp, 0);
    char *str = (char *)malloc(n + 1);
    if (!str) { bip388_sbuf_free(&b); return BIP388_ERR_NO_MEMORY; }
    bip388_dt_format(dt, str, n + 1);
    out->entry = NULL;
    out->other_str = str;
    bip388_sbuf_free(&b);
    return BIP388_OK;
}

/* ============================================================ */
/* Render                                                       */
/* ============================================================ */

static bip388_err_t render_key(const bip388_ke_t *ke, bool canonical, bip388_sbuf_t *b) {
    if (ke->type == BIP388_KE_PLAIN) {
        if (canonical) return bip388_sbuf_pushf(b, "@%u", ke->u.plain_index);
        return bip388_sbuf_pushf(b, "@%u/<%u;%u>/*", ke->u.plain_index, ke->num1, ke->num2);
    }
    bip388_err_t err = bip388_sbuf_push(b, BIP388_LIT("musig("));
    if (err) return err;
    for (size_t i = 0; i < ke->u.musig.n_indices; ++i) {
        if (i > 0) { err = bip388_sbuf_pushc(b, ','); if (err) return err; }
        err = bip388_sbuf_pushf(b, "@%u", ke->u.musig.indices[i]);
        if (err) return err;
    }
    if (canonical) return bip388_sbuf_pushc(b, ')');
    return bip388_sbuf_pushf(b, ")/<%u;%u>/*", ke->num1, ke->num2);
}

static bip388_err_t render_key_indices(const bip388_ke_t *keys, size_t n, bool canonical,
                                       bip388_sbuf_t *b) {
    if (n == 0) return BIP388_OK;
    if (n == 1) return render_key(&keys[0], canonical, b);
    for (size_t i = 0; i + 1 < n; ++i) {
        if (i > 0) { bip388_err_t err = bip388_sbuf_push(b, BIP388_LIT(", ")); if (err) return err; }
        bip388_err_t err = render_key(&keys[i], canonical, b);
        if (err) return err;
    }
    bip388_err_t err = bip388_sbuf_push(b, BIP388_LIT(" and "));
    if (err) return err;
    return render_key(&keys[n - 1], canonical, b);
}

static bip388_err_t render_field(const bip388_ct_token_t *tok,
                                 const bip388_field_value_t *v,
                                 bool canonical, bip388_sbuf_t *b) {
    char tmp[64];
    switch (tok->bkind) {
        case BK_KEY: return render_key(v->key, canonical, b);
        case BK_KEYLIST:
            return render_key_indices(v->keylist.items, v->keylist.n, canonical, b);
        case BK_THRESHOLD:
        case BK_BLOCKS:
        case BK_BLOCK_HEIGHT:
            return bip388_sbuf_pushf(b, "%u", v->num);
        case BK_RELATIVE_TIME: {
            uint32_t t = (v->num & ~BIP388_SEQUENCE_LOCKTIME_TYPE_FLAG) * 512u;
            bip388_format_seconds(t, tmp, sizeof(tmp));
            return bip388_sbuf_push(b, tmp, strlen(tmp));
        }
        case BK_TIMESTAMP:
            bip388_format_utc_date(v->num, tmp, sizeof(tmp));
            return bip388_sbuf_push(b, tmp, strlen(tmp));
        default:
            return BIP388_ERR_FORMAT_ERROR;
    }
}

static bip388_err_t render_entry(const bip388_spec_entry_t *entry,
                                 const bip388_field_value_t *fields,
                                 bool canonical, bip388_sbuf_t *b) {
    for (uint8_t i = 0; i < entry->n_cleartext; ++i) {
        const bip388_ct_token_t *tok = &entry->cleartext[i];
        bip388_err_t err;
        if (tok->kind == CT_LITERAL) {
            err = bip388_sbuf_push(b, tok->literal, strlen(tok->literal));
        } else {
            err = render_field(tok, &fields[tok->field_idx], canonical, b);
        }
        if (err) return err;
    }
    return BIP388_OK;
}

/* ============================================================ */
/* Score                                                        */
/* ============================================================ */

static uint64_t entry_score(const bip388_spec_entry_t *entry,
                            const bip388_field_value_t *fields) {
    uint64_t score = entry->plain_pattern_count;
    if (entry->musig_pattern_count > 0) {
        /* Find threshold + keys fields. */
        uint32_t threshold = 0;
        size_t n_keys = (size_t)-1;
        for (uint8_t i = 0; i < entry->n_fields; ++i) {
            const bip388_spec_field_t *f = &entry->fields[i];
            if (f->kind == BK_THRESHOLD) threshold = fields[i].num;
            if (f->kind == BK_KEYLIST) n_keys = fields[i].keylist.n;
        }
        if (n_keys != (size_t)-1 && threshold == n_keys)
            score += entry->musig_pattern_count;
    }
    return score;
}

/* ============================================================ */
/* Canonical-derivation check + factorial product               */
/* ============================================================ */

/* For each distinct KeyExpression "type" (plain idx OR musig indices),
 * collect (num1, num2) pairs across all placeholders. After sorting,
 * pairs must equal (0,1), (2,3), .... */

typedef struct {
    /* key signature: type byte + plain_index OR (n_indices, indices...) */
    uint8_t buf[64];
    size_t len;
    uint32_t *pairs;  /* alternating num1, num2 */
    size_t n_pairs;
    size_t cap;
} key_bucket_t;

typedef struct {
    key_bucket_t *items;
    size_t n;
    size_t cap;
} key_buckets_t;

static int ke_signature(const bip388_ke_t *ke, uint8_t *out, size_t out_cap) {
    if (out_cap < 8) return -1;
    size_t pos = 0;
    if (ke->type == BIP388_KE_PLAIN) {
        out[pos++] = 0;
        out[pos++] = (uint8_t)(ke->u.plain_index >> 24);
        out[pos++] = (uint8_t)(ke->u.plain_index >> 16);
        out[pos++] = (uint8_t)(ke->u.plain_index >> 8);
        out[pos++] = (uint8_t)ke->u.plain_index;
        return (int)pos;
    }
    out[pos++] = 1;
    size_t n = ke->u.musig.n_indices;
    if (pos + 4 + n * 4 > out_cap) return -1;
    out[pos++] = (uint8_t)(n >> 24);
    out[pos++] = (uint8_t)(n >> 16);
    out[pos++] = (uint8_t)(n >> 8);
    out[pos++] = (uint8_t)n;
    for (size_t i = 0; i < n; ++i) {
        uint32_t v = ke->u.musig.indices[i];
        out[pos++] = (uint8_t)(v >> 24);
        out[pos++] = (uint8_t)(v >> 16);
        out[pos++] = (uint8_t)(v >> 8);
        out[pos++] = (uint8_t)v;
    }
    return (int)pos;
}

static key_bucket_t *buckets_find_or_create(key_buckets_t *b, const uint8_t *sig, size_t siglen) {
    for (size_t i = 0; i < b->n; ++i) {
        if (b->items[i].len == siglen && memcmp(b->items[i].buf, sig, siglen) == 0)
            return &b->items[i];
    }
    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 8;
        key_bucket_t *np = (key_bucket_t *)realloc(b->items, nc * sizeof(*np));
        if (!np) return NULL;
        b->items = np;
        b->cap = nc;
    }
    key_bucket_t *nb = &b->items[b->n++];
    memcpy(nb->buf, sig, siglen);
    nb->len = siglen;
    nb->pairs = NULL;
    nb->n_pairs = 0;
    nb->cap = 0;
    return nb;
}

static int bucket_push_pair(key_bucket_t *b, uint32_t n1, uint32_t n2) {
    if (b->n_pairs * 2 == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4;
        uint32_t *np = (uint32_t *)realloc(b->pairs, nc * sizeof(uint32_t));
        if (!np) return -1;
        b->pairs = np;
        b->cap = nc;
    }
    b->pairs[b->n_pairs * 2] = n1;
    b->pairs[b->n_pairs * 2 + 1] = n2;
    b->n_pairs++;
    return 0;
}

static int cmp_pair(const void *a, const void *b) {
    const uint32_t *aa = (const uint32_t *)a;
    const uint32_t *bb = (const uint32_t *)b;
    if (aa[0] != bb[0]) return aa[0] < bb[0] ? -1 : 1;
    if (aa[1] != bb[1]) return aa[1] < bb[1] ? -1 : 1;
    return 0;
}

static bool are_key_derivations_canonical(const bip388_dt_t *dt) {
    bip388_placeholder_t *phs = NULL;
    size_t n = 0;
    if (bip388_dt_placeholders(dt, &phs, &n) != BIP388_OK) return false;
    key_buckets_t bk = {0};
    bool ok = true;
    for (size_t i = 0; i < n; ++i) {
        uint8_t sig[256];
        int slen = ke_signature(phs[i].ke, sig, sizeof(sig));
        if (slen < 0) { ok = false; break; }
        key_bucket_t *b = buckets_find_or_create(&bk, sig, (size_t)slen);
        if (!b) { ok = false; break; }
        if (bucket_push_pair(b, phs[i].ke->num1, phs[i].ke->num2) < 0) { ok = false; break; }
    }
    if (ok) {
        for (size_t i = 0; i < bk.n; ++i) {
            qsort(bk.items[i].pairs, bk.items[i].n_pairs, sizeof(uint32_t) * 2, cmp_pair);
            for (size_t j = 0; j < bk.items[i].n_pairs; ++j) {
                uint32_t expected1 = (uint32_t)(2 * j);
                uint32_t expected2 = (uint32_t)(2 * j + 1);
                if (bk.items[i].pairs[2 * j] != expected1 ||
                    bk.items[i].pairs[2 * j + 1] != expected2) { ok = false; break; }
            }
            if (!ok) break;
        }
    }
    for (size_t i = 0; i < bk.n; ++i) free(bk.items[i].pairs);
    free(bk.items);
    bip388_dt_placeholders_free(phs);
    return ok;
}

static uint64_t key_derivation_orderings_count(const bip388_dt_t *dt) {
    bip388_placeholder_t *phs = NULL;
    size_t n = 0;
    if (bip388_dt_placeholders(dt, &phs, &n) != BIP388_OK) return 1;
    key_buckets_t bk = {0};
    for (size_t i = 0; i < n; ++i) {
        uint8_t sig[256];
        int slen = ke_signature(phs[i].ke, sig, sizeof(sig));
        if (slen < 0) {
            for (size_t j = 0; j < bk.n; ++j) free(bk.items[j].pairs);
            free(bk.items);
            bip388_dt_placeholders_free(phs);
            return 1;
        }
        key_bucket_t *b = buckets_find_or_create(&bk, sig, (size_t)slen);
        if (!b) break;
        bucket_push_pair(b, phs[i].ke->num1, phs[i].ke->num2);
    }
    uint64_t product = 1;
    for (size_t i = 0; i < bk.n; ++i) {
        uint64_t f = 1;
        for (uint64_t j = 1; j <= bk.items[i].n_pairs; ++j) f = bip388_sat_mul(f, j);
        product = bip388_sat_mul(product, f);
        free(bk.items[i].pairs);
    }
    free(bk.items);
    bip388_dt_placeholders_free(phs);
    return product;
}

/* ============================================================ */
/* Display ordering for tapleaves                               */
/* ============================================================ */

static int cmp_key_sig(const bip388_ke_t *a, const bip388_ke_t *b) {
    int a_is_musig = (a->type == BIP388_KE_MUSIG) ? 1 : 0;
    int b_is_musig = (b->type == BIP388_KE_MUSIG) ? 1 : 0;
    if (a_is_musig != b_is_musig) return a_is_musig - b_is_musig;
    if (!a_is_musig)
        return (a->u.plain_index == b->u.plain_index) ? 0
             : (a->u.plain_index < b->u.plain_index ? -1 : 1);
    /* Both musig. */
    if (a->u.musig.n_indices != b->u.musig.n_indices)
        return a->u.musig.n_indices < b->u.musig.n_indices ? -1 : 1;
    for (size_t i = 0; i < a->u.musig.n_indices; ++i) {
        if (a->u.musig.indices[i] != b->u.musig.indices[i])
            return a->u.musig.indices[i] < b->u.musig.indices[i] ? -1 : 1;
    }
    return 0;
}

static int leaf_entry_order(const bip388_class_instance_t *c) {
    if (!c->entry) return (int)bip388_tapleaf_specs_count; /* Other goes last */
    return (int)(c->entry - bip388_tapleaf_specs);
}

/* Composite comparator: matches the Rust display_cmp tie-breakers. */
static int cmp_leaf(const void *pa, const void *pb) {
    const bip388_class_instance_t *a = (const bip388_class_instance_t *)pa;
    const bip388_class_instance_t *b = (const bip388_class_instance_t *)pb;
    int oa = leaf_entry_order(a);
    int ob = leaf_entry_order(b);
    if (oa != ob) return oa < ob ? -1 : 1;
    if (!a->entry) {
        const char *sa = a->other_str ? a->other_str : "";
        const char *sb = b->other_str ? b->other_str : "";
        return strcmp(sa, sb);
    }
    const bip388_spec_entry_t *e = a->entry;
    /* keys.len (1), threshold (2), key/key1/key2, blocks/time/etc. */
    int idx_keys = -1, idx_thresh = -1;
    int idx_key = -1, idx_key1 = -1, idx_key2 = -1;
    int idx_blocks = -1, idx_rt = -1, idx_bh = -1, idx_ts = -1;
    for (uint8_t i = 0; i < e->n_fields; ++i) {
        const char *n = e->fields[i].name;
        if (!strcmp(n, "keys")) idx_keys = i;
        else if (!strcmp(n, "threshold")) idx_thresh = i;
        else if (!strcmp(n, "key")) idx_key = i;
        else if (!strcmp(n, "key1")) idx_key1 = i;
        else if (!strcmp(n, "key2")) idx_key2 = i;
        else if (!strcmp(n, "blocks")) idx_blocks = i;
        else if (!strcmp(n, "relative_time")) idx_rt = i;
        else if (!strcmp(n, "block_height")) idx_bh = i;
        else if (!strcmp(n, "timestamp")) idx_ts = i;
    }
    if (idx_keys >= 0) {
        size_t na = a->fields[idx_keys].keylist.n;
        size_t nb = b->fields[idx_keys].keylist.n;
        if (na != nb) return na < nb ? -1 : 1;
    }
    if (idx_thresh >= 0) {
        uint32_t ta = a->fields[idx_thresh].num;
        uint32_t tb = b->fields[idx_thresh].num;
        if (ta != tb) return ta < tb ? -1 : 1;
    }
    int ks[] = {idx_key, idx_key1, idx_key2};
    for (size_t i = 0; i < 3; ++i) {
        int idx = ks[i];
        if (idx < 0) continue;
        int r = cmp_key_sig(a->fields[idx].key, b->fields[idx].key);
        if (r != 0) return r;
    }
    int ns[] = {idx_blocks, idx_rt, idx_bh, idx_ts};
    for (size_t i = 0; i < 4; ++i) {
        int idx = ns[i];
        if (idx < 0) continue;
        uint32_t na = a->fields[idx].num;
        uint32_t nb = b->fields[idx].num;
        if (na != nb) return na < nb ? -1 : 1;
    }
    return 0;
}

/* ============================================================ */
/* Public API                                                   */
/* ============================================================ */

uint64_t bip388_confusion_score(const bip388_dt_t *dt) {
    bip388_class_instance_t cls;
    if (classify_top_level(dt, &cls) != BIP388_OK) return 1;
    uint64_t base;
    if (cls.entry && (!strcmp(cls.entry->name, "Taproot") ||
                      !strcmp(cls.entry->name, "TaprootMusig"))) {
        base = entry_score(cls.entry, cls.fields);
        /* leaves */
        size_t n_leaves = 0;
        const bip388_class_instance_t *leaves = NULL;
        for (uint8_t i = 0; i < cls.entry->n_fields; ++i) {
            if (cls.entry->fields[i].kind == BK_LEAVES) {
                n_leaves = cls.fields[i].leaves.n;
                leaves = cls.fields[i].leaves.items;
                break;
            }
        }
        for (size_t i = 0; i < n_leaves; ++i) {
            uint64_t s = leaves[i].entry ? entry_score(leaves[i].entry, leaves[i].fields) : 1;
            base = bip388_sat_mul(base, s);
        }
        if (n_leaves > 1) {
            uint64_t i = 1;
            uint64_t hi = (uint64_t)(2 * n_leaves - 3);
            while (i <= hi) {
                base = bip388_sat_mul(base, i);
                i += 2;
            }
        }
    } else if (cls.entry) {
        base = entry_score(cls.entry, cls.fields);
    } else {
        base = 1;
    }
    uint64_t factor = key_derivation_orderings_count(dt);
    uint64_t result = bip388_sat_mul(base, factor);
    class_instance_free(&cls);
    return result;
}

void bip388_cleartext_free(char **lines, size_t n) {
    if (!lines) return;
    for (size_t i = 0; i < n; ++i) free(lines[i]);
    free(lines);
}

static bip388_err_t emit_line(char ***lines, size_t *n, size_t *cap, char *s) {
    if (*n == *cap) {
        size_t nc = *cap ? *cap * 2 : 8;
        char **np = (char **)realloc(*lines, nc * sizeof(*np));
        if (!np) { free(s); return BIP388_ERR_NO_MEMORY; }
        *lines = np;
        *cap = nc;
    }
    (*lines)[(*n)++] = s;
    return BIP388_OK;
}

bip388_err_t bip388_to_cleartext(const bip388_dt_t *dt,
                                 char ***out_lines, size_t *out_n,
                                 bool *has_cleartext) {
    *out_lines = NULL;
    *out_n = 0;
    *has_cleartext = false;
    size_t cap = 0;
    bip388_err_t err;

    if (!are_key_derivations_canonical(dt)) {
        size_t need = bip388_dt_format(dt, NULL, 0);
        char *s = (char *)malloc(need + 1);
        if (!s) return BIP388_ERR_NO_MEMORY;
        bip388_dt_format(dt, s, need + 1);
        return emit_line(out_lines, out_n, &cap, s);
    }

    bip388_class_instance_t cls;
    err = classify_top_level(dt, &cls);
    if (err) return err;

    if (!cls.entry) {
        size_t need = bip388_dt_format(dt, NULL, 0);
        char *s = (char *)malloc(need + 1);
        if (!s) { class_instance_free(&cls); return BIP388_ERR_NO_MEMORY; }
        bip388_dt_format(dt, s, need + 1);
        err = emit_line(out_lines, out_n, &cap, s);
        class_instance_free(&cls);
        return err;
    }

    bool is_tr = !strcmp(cls.entry->name, "Taproot") || !strcmp(cls.entry->name, "TaprootMusig");

    /* Primary line. */
    bip388_sbuf_t b;
    bip388_sbuf_init(&b);
    err = render_entry(cls.entry, cls.fields, true, &b);
    if (err) { bip388_sbuf_free(&b); class_instance_free(&cls); return err; }
    char *primary = (char *)malloc(b.len + 1);
    if (!primary) { bip388_sbuf_free(&b); class_instance_free(&cls); return BIP388_ERR_NO_MEMORY; }
    memcpy(primary, b.data, b.len);
    primary[b.len] = '\0';
    bip388_sbuf_free(&b);
    err = emit_line(out_lines, out_n, &cap, primary);
    if (err) { class_instance_free(&cls); return err; }

    if (!is_tr) {
        *has_cleartext = true;
        class_instance_free(&cls);
        return BIP388_OK;
    }

    /* Tap-tree leaves. */
    bip388_class_instance_t *leaves = NULL;
    size_t n_leaves = 0;
    for (uint8_t i = 0; i < cls.entry->n_fields; ++i) {
        if (cls.entry->fields[i].kind == BK_LEAVES) {
            leaves = cls.fields[i].leaves.items;
            n_leaves = cls.fields[i].leaves.n;
            break;
        }
    }
    if (n_leaves > 1) qsort(leaves, n_leaves, sizeof(*leaves), cmp_leaf);

    bool all_have = true;
    for (size_t i = 0; i < n_leaves; ++i) {
        bip388_class_instance_t *leaf = &leaves[i];
        if (!leaf->entry) {
            const char *s = leaf->other_str ? leaf->other_str : "";
            char *copy = (char *)malloc(strlen(s) + 1);
            if (!copy) { class_instance_free(&cls); return BIP388_ERR_NO_MEMORY; }
            strcpy(copy, s);
            err = emit_line(out_lines, out_n, &cap, copy);
            if (err) { class_instance_free(&cls); return err; }
            all_have = false;
            continue;
        }
        bip388_sbuf_t lb;
        bip388_sbuf_init(&lb);
        err = render_entry(leaf->entry, leaf->fields, true, &lb);
        if (err) { bip388_sbuf_free(&lb); class_instance_free(&cls); return err; }
        char *line = (char *)malloc(lb.len + 1);
        if (!line) { bip388_sbuf_free(&lb); class_instance_free(&cls); return BIP388_ERR_NO_MEMORY; }
        memcpy(line, lb.data, lb.len);
        line[lb.len] = '\0';
        bip388_sbuf_free(&lb);
        err = emit_line(out_lines, out_n, &cap, line);
        if (err) { class_instance_free(&cls); return err; }
    }
    *has_cleartext = all_have;
    class_instance_free(&cls);
    return BIP388_OK;
}
