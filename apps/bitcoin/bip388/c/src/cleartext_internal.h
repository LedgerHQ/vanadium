/* Cleartext internals exposed for testing.
 *
 * NOT part of the public API — used by `tests/` to inspect the result
 * of classification without going through `bip388_to_cleartext`. The
 * class instance type lives here so it can be shared between the
 * cleartext implementation and the tests.
 */
#ifndef BIP388_CLEARTEXT_INTERNAL_H
#define BIP388_CLEARTEXT_INTERNAL_H

#include "../include/bip388.h"
#include "gen/cleartext_gen.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bip388_class_instance bip388_class_instance_t;

typedef struct {
    bip388_binding_kind_t kind;
    const bip388_ke_t *key;
    struct {
        bip388_ke_t *items;
        size_t n;
        bool owned;
    } keylist;
    uint32_t num;
    struct {
        bip388_class_instance_t *items;
        size_t n;
    } leaves;
} bip388_field_value_t;

struct bip388_class_instance {
    const bip388_spec_entry_t *entry; /* NULL when Other */
    char *other_str;
    bip388_field_value_t *fields;
};

bip388_err_t bip388_classify_internal(const bip388_dt_t *dt,
                                      bip388_class_instance_t *out);
bip388_err_t bip388_classify_as_tapleaf_internal(const bip388_dt_t *dt,
                                                 bip388_class_instance_t *out);
void bip388_class_instance_free(bip388_class_instance_t *c);

#ifdef __cplusplus
}
#endif

#endif
