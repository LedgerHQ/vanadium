#include <stdio.h>

#include "test_framework.h"

int g_test_failures = 0;
const char *g_test_current = NULL;

/* Test declarations (defined in their respective files). */
#define T(name) void test_##name(void);
#include "test_list.inc"
#undef T

int main(void) {
    int total = 0;
#define T(name) do { \
        g_test_current = #name; \
        int before = g_test_failures; \
        test_##name(); \
        if (g_test_failures == before) { \
            /* passed silently */ \
        } else { \
            fprintf(stderr, "FAIL: %s\n", #name); \
        } \
        total++; \
    } while (0);
#include "test_list.inc"
#undef T

    if (g_test_failures) {
        fprintf(stderr, "\n%d / %d tests FAILED\n", g_test_failures, total);
        return 1;
    }
    fprintf(stderr, "%d tests OK\n", total);
    return 0;
}
