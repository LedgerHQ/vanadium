/* Trivially small test harness. Tests register themselves through
 * `TEST(name)` macros; `test_main.c` collects everything via the
 * common TEST_LIST(X) macro and invokes them in order.
 */
#ifndef BIP388_TEST_FRAMEWORK_H
#define BIP388_TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int g_test_failures;
extern const char *g_test_current;

#define T_PASS()  do {} while (0)
#define T_FAIL(...) do { \
    fprintf(stderr, "  %s: ", g_test_current); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    g_test_failures++; \
    return; \
} while (0)

#define T_ASSERT(cond) do { \
    if (!(cond)) { T_FAIL("assertion failed: %s (at %s:%d)", #cond, __FILE__, __LINE__); } \
} while (0)

#define T_EQ_INT(a, b) do { \
    long long aa = (long long)(a); \
    long long bb = (long long)(b); \
    if (aa != bb) { T_FAIL("expected %lld == %lld (got %s != %s at %s:%d)", aa, bb, #a, #b, __FILE__, __LINE__); } \
} while (0)

#define T_EQ_UINT(a, b) do { \
    unsigned long long aa = (unsigned long long)(a); \
    unsigned long long bb = (unsigned long long)(b); \
    if (aa != bb) { T_FAIL("expected %llu == %llu (at %s:%d)", aa, bb, __FILE__, __LINE__); } \
} while (0)

#define T_EQ_STR(a, b) do { \
    const char *aa = (a); \
    const char *bb = (b); \
    if (!aa || !bb || strcmp(aa, bb) != 0) { \
        T_FAIL("expected %s == %s (got %s vs %s at %s:%d)", \
               #a, #b, aa ? aa : "(null)", bb ? bb : "(null)", __FILE__, __LINE__); \
    } \
} while (0)

#define TEST(name) void test_##name(void)

#endif /* BIP388_TEST_FRAMEWORK_H */
