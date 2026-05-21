#ifndef BIP388_TEST_VECTORS_GEN_H
#define BIP388_TEST_VECTORS_GEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *template;
    bool has_confusion_score;
    uint64_t confusion_score;
    bool has_cleartext_array;
    const char *const *cleartext;
    size_t n_cleartext;
    bool has_has_cleartext;
    bool has_cleartext;
} bip388_test_vector_t;

extern const bip388_test_vector_t bip388_test_vectors[];
extern const size_t bip388_test_vectors_count;

#endif
