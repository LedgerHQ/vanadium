#include "../include/bip388.h"
#include "../src/cleartext_internal.h"
#include "../src/gen/cleartext_gen.h"
#include "../src/gen/test_vectors_gen.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

static bip388_dt_t *parse_or_die(const char *s) {
    bip388_dt_t *dt = NULL;
    bip388_err_t err = bip388_dt_from_str(s, &dt);
    if (err) {
        fprintf(stderr, "parse failed for %s: %s\n", s, bip388_err_name(err));
        abort();
    }
    return dt;
}

TEST(cleartext_vectors_confusion_score) {
    for (size_t i = 0; i < bip388_test_vectors_count; ++i) {
        const bip388_test_vector_t *v = &bip388_test_vectors[i];
        if (!v->has_confusion_score) continue;
        bip388_dt_t *dt = parse_or_die(v->template);
        uint64_t got = bip388_confusion_score(dt);
        if (got != v->confusion_score) {
            T_FAIL("confusion_score mismatch for %s: got %llu expected %llu",
                   v->template, (unsigned long long)got,
                   (unsigned long long)v->confusion_score);
        }
        bip388_dt_free(dt); free(dt);
    }
}

TEST(cleartext_vectors_to_cleartext) {
    for (size_t i = 0; i < bip388_test_vectors_count; ++i) {
        const bip388_test_vector_t *v = &bip388_test_vectors[i];
        if (!v->has_cleartext_array || !v->has_has_cleartext) continue;
        bip388_dt_t *dt = parse_or_die(v->template);
        char **lines = NULL;
        size_t n = 0;
        bool has = false;
        T_EQ_INT(bip388_to_cleartext(dt, &lines, &n, &has), BIP388_OK);
        if (has != v->has_cleartext) {
            T_FAIL("has_cleartext mismatch for %s (got %d expected %d)",
                   v->template, has, v->has_cleartext);
        }
        if (n != v->n_cleartext) {
            T_FAIL("line count mismatch for %s (got %zu expected %zu)",
                   v->template, n, v->n_cleartext);
        }
        for (size_t j = 0; j < n; ++j) {
            if (strcmp(lines[j], v->cleartext[j]) != 0) {
                T_FAIL("line %zu mismatch for %s:\n  got      %s\n  expected %s",
                       j, v->template, lines[j], v->cleartext[j]);
            }
        }
        bip388_cleartext_free(lines, n);
        bip388_dt_free(dt); free(dt);
    }
}

TEST(cleartext_vectors_has_cleartext) {
    for (size_t i = 0; i < bip388_test_vectors_count; ++i) {
        const bip388_test_vector_t *v = &bip388_test_vectors[i];
        if (v->has_cleartext_array) continue;
        if (!v->has_has_cleartext) continue;
        bip388_dt_t *dt = parse_or_die(v->template);
        char **lines = NULL;
        size_t n = 0;
        bool has = false;
        T_EQ_INT(bip388_to_cleartext(dt, &lines, &n, &has), BIP388_OK);
        if (has != v->has_cleartext) {
            T_FAIL("has_cleartext mismatch for %s (got %d expected %d)",
                   v->template, has, v->has_cleartext);
        }
        bip388_cleartext_free(lines, n);
        bip388_dt_free(dt); free(dt);
    }
}

TEST(cleartext_spec_shape_uniqueness) {
    /* Each section's cleartext shapes (literals + sentinel for dynamic
     * fields) must be unique, otherwise two entries would be
     * indistinguishable to the runtime parser. */
    const char *sentinel = "\x1";
    char shapes[64][512];
    const char *names[64];
    size_t n_shapes;

    /* top_level */
    n_shapes = 0;
    for (size_t i = 0; i < bip388_top_level_specs_count; ++i) {
        const bip388_spec_entry_t *e = &bip388_top_level_specs[i];
        char *p = shapes[n_shapes];
        char *end = p + sizeof(shapes[0]);
        for (uint8_t j = 0; j < e->n_cleartext; ++j) {
            const char *s = (e->cleartext[j].kind == CT_LITERAL)
                              ? e->cleartext[j].literal : sentinel;
            size_t l = strlen(s);
            if (p + l + 1 >= end) break;
            memcpy(p, s, l);
            p += l;
        }
        *p = '\0';
        names[n_shapes++] = e->name;
    }
    for (size_t i = 0; i < n_shapes; ++i)
        for (size_t j = i + 1; j < n_shapes; ++j)
            if (!strcmp(shapes[i], shapes[j]))
                T_FAIL("top_level shape collision: %s and %s", names[i], names[j]);

    /* tapleaf */
    n_shapes = 0;
    for (size_t i = 0; i < bip388_tapleaf_specs_count; ++i) {
        const bip388_spec_entry_t *e = &bip388_tapleaf_specs[i];
        char *p = shapes[n_shapes];
        char *end = p + sizeof(shapes[0]);
        for (uint8_t j = 0; j < e->n_cleartext; ++j) {
            const char *s = (e->cleartext[j].kind == CT_LITERAL)
                              ? e->cleartext[j].literal : sentinel;
            size_t l = strlen(s);
            if (p + l + 1 >= end) break;
            memcpy(p, s, l);
            p += l;
        }
        *p = '\0';
        names[n_shapes++] = e->name;
    }
    for (size_t i = 0; i < n_shapes; ++i)
        for (size_t j = i + 1; j < n_shapes; ++j)
            if (!strcmp(shapes[i], shapes[j]))
                T_FAIL("tapleaf shape collision: %s and %s", names[i], names[j]);
}

/* These tests verify that the classifier propagates the musig's
 * num1/num2 onto each synthesized plain key. They call the classifier
 * directly via the cleartext-internal API because the canonical-
 * derivation guard in `to_cleartext` would short-circuit the
 * <2;3>/<4;5> cases to the raw-descriptor fallback. */

static int idx_of_field(const bip388_spec_entry_t *e, const char *name) {
    for (uint8_t i = 0; i < e->n_fields; ++i)
        if (strcmp(e->fields[i].name, name) == 0) return (int)i;
    return -1;
}

TEST(cleartext_musig_preserves_derivations_internal_key) {
    bip388_dt_t *dt = parse_or_die("tr(musig(@0,@1)/<2;3>/*,pk(@2/**))");
    bip388_class_instance_t cls = {0};
    T_EQ_INT(bip388_classify_internal(dt, &cls), BIP388_OK);
    T_ASSERT(cls.entry != NULL);
    T_EQ_STR(cls.entry->name, "TaprootMusig");
    int t_idx = idx_of_field(cls.entry, "threshold");
    int k_idx = idx_of_field(cls.entry, "keys");
    int l_idx = idx_of_field(cls.entry, "leaves");
    T_ASSERT(t_idx >= 0 && k_idx >= 0 && l_idx >= 0);
    T_EQ_UINT(cls.fields[t_idx].num, 2);
    T_EQ_UINT(cls.fields[k_idx].keylist.n, 2);
    for (size_t i = 0; i < 2; ++i) {
        T_EQ_INT(cls.fields[k_idx].keylist.items[i].type, BIP388_KE_PLAIN);
        T_EQ_UINT(cls.fields[k_idx].keylist.items[i].num1, 2);
        T_EQ_UINT(cls.fields[k_idx].keylist.items[i].num2, 3);
    }
    T_EQ_UINT(cls.fields[k_idx].keylist.items[0].u.plain_index, 0);
    T_EQ_UINT(cls.fields[k_idx].keylist.items[1].u.plain_index, 1);
    T_EQ_UINT(cls.fields[l_idx].leaves.n, 1);
    bip388_class_instance_free(&cls);
    bip388_dt_free(dt); free(dt);
}

TEST(cleartext_musig_preserves_derivations_tapleaf) {
    bip388_dt_t *dt = parse_or_die("tr(@0/**,pk(musig(@1,@2)/<4;5>/*))");
    bip388_class_instance_t cls = {0};
    T_EQ_INT(bip388_classify_internal(dt, &cls), BIP388_OK);
    T_ASSERT(cls.entry != NULL);
    T_EQ_STR(cls.entry->name, "Taproot");
    int l_idx = idx_of_field(cls.entry, "leaves");
    T_ASSERT(l_idx >= 0);
    T_EQ_UINT(cls.fields[l_idx].leaves.n, 1);
    const bip388_class_instance_t *leaf = &cls.fields[l_idx].leaves.items[0];
    T_ASSERT(leaf->entry != NULL);
    T_EQ_STR(leaf->entry->name, "Multisig");
    int t_idx = idx_of_field(leaf->entry, "threshold");
    int k_idx = idx_of_field(leaf->entry, "keys");
    T_EQ_UINT(leaf->fields[t_idx].num, 2);
    T_EQ_UINT(leaf->fields[k_idx].keylist.n, 2);
    for (size_t i = 0; i < 2; ++i) {
        T_EQ_UINT(leaf->fields[k_idx].keylist.items[i].num1, 4);
        T_EQ_UINT(leaf->fields[k_idx].keylist.items[i].num2, 5);
    }
    bip388_class_instance_free(&cls);
    bip388_dt_free(dt); free(dt);
}

TEST(cleartext_musig_standard_derivation) {
    bip388_dt_t *dt = parse_or_die("tr(musig(@0,@1)/**)");
    bip388_class_instance_t cls = {0};
    T_EQ_INT(bip388_classify_internal(dt, &cls), BIP388_OK);
    T_ASSERT(cls.entry != NULL);
    T_EQ_STR(cls.entry->name, "TaprootMusig");
    int t_idx = idx_of_field(cls.entry, "threshold");
    int k_idx = idx_of_field(cls.entry, "keys");
    int l_idx = idx_of_field(cls.entry, "leaves");
    T_EQ_UINT(cls.fields[t_idx].num, 2);
    T_EQ_UINT(cls.fields[k_idx].keylist.n, 2);
    for (size_t i = 0; i < 2; ++i) {
        T_EQ_UINT(cls.fields[k_idx].keylist.items[i].num1, 0);
        T_EQ_UINT(cls.fields[k_idx].keylist.items[i].num2, 1);
    }
    T_EQ_UINT(cls.fields[l_idx].leaves.n, 0);
    bip388_class_instance_free(&cls);
    bip388_dt_free(dt); free(dt);
}
