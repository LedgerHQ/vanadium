/* C port of `src/lib.rs` unit tests. */

#include "../include/bip388.h"
#include "test_framework.h"

#include <stdlib.h>
#include <string.h>

#define H 0x80000000u
#define XPUB_C "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
#define XPUB_A "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"
#define XPUB_B "tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"

/* ============================================================ */
/* KeyOrigin / derivation step (covers _parse_derivation_step)  */
/* ============================================================ */

static int parse_origin(const char *s, bip388_key_origin_t *out) {
    return bip388_key_origin_parse(s, strlen(s), out);
}

TEST(derivation_step_success) {
    bip388_key_origin_t o;
    /* 8-hex fingerprint plus hardened/unhardened steps. */
    T_EQ_INT(parse_origin("012345af/0'/1'/3", &o), BIP388_OK);
    T_EQ_UINT(o.fingerprint, 0x012345af);
    T_EQ_UINT(o.n_path, 3);
    T_EQ_UINT(o.path[0], 0u + H);
    T_EQ_UINT(o.path[1], 1u + H);
    T_EQ_UINT(o.path[2], 3u);
    bip388_key_origin_free(&o);
    T_EQ_INT(parse_origin("012345af/2147483647", &o), BIP388_OK);
    T_EQ_UINT(o.path[0], H - 1);
    bip388_key_origin_free(&o);
    T_EQ_INT(parse_origin("012345af/2147483647'", &o), BIP388_OK);
    T_EQ_UINT(o.path[0], H - 1 + H);
    bip388_key_origin_free(&o);
}

TEST(derivation_step_errors) {
    bip388_key_origin_t o;
    /* Step values exceeding 2^31 are rejected. */
    T_ASSERT(parse_origin("012345af/2147483648", &o) != BIP388_OK);
    T_ASSERT(parse_origin("012345af/2147483648'", &o) != BIP388_OK);
}

TEST(key_origin_success) {
    bip388_key_origin_t o;
    T_EQ_INT(parse_origin("012345af/0'/1'/3", &o), BIP388_OK);
    T_EQ_UINT(o.fingerprint, 0x012345afu);
    T_EQ_UINT(o.n_path, 3);
    bip388_key_origin_free(&o);

    T_EQ_INT(parse_origin("012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89", &o), BIP388_OK);
    T_EQ_UINT(o.n_path, 11);
    bip388_key_origin_free(&o);

    T_EQ_INT(parse_origin("012345af", &o), BIP388_OK);
    T_EQ_UINT(o.n_path, 0);
    bip388_key_origin_free(&o);
}

TEST(key_origin_errors) {
    bip388_key_origin_t o;
    T_ASSERT(parse_origin("[01234567/0'/1'/3]", &o) != BIP388_OK);
    T_ASSERT(parse_origin("0123456/0'/1'/3", &o) != BIP388_OK);
    T_ASSERT(parse_origin("012345678/0'/1'/3", &o) != BIP388_OK);
    T_ASSERT(parse_origin("012345ag/0'/1'/2147483648", &o) != BIP388_OK);
}

/* ============================================================ */
/* Key expression (indirect via DescriptorTemplate.from_str)    */
/* ============================================================ */

static int dt_parses(const char *s) {
    bip388_dt_t *dt = NULL;
    bip388_err_t err = bip388_dt_from_str(s, &dt);
    if (err) return 0;
    bip388_dt_free(dt); free(dt);
    return 1;
}

static int dt_error(const char *s, bip388_err_t expected) {
    bip388_dt_t *dt = NULL;
    bip388_err_t err = bip388_dt_from_str(s, &dt);
    if (dt) { bip388_dt_free(dt); free(dt); }
    return err == expected;
}

TEST(key_expression_success) {
    /* All forms accepted at top-level via pkh(...). */
    T_ASSERT(dt_parses("pkh(@0/**)"));
    T_ASSERT(dt_parses("pkh(@4294967295/**)"));
    T_ASSERT(dt_parses("pkh(@1/<0;1>/*)"));
    T_ASSERT(dt_parses("pkh(@2/<3;4>/*)"));
    T_ASSERT(dt_parses("pkh(@3/<1;9>/*)"));
}

TEST(key_expression_errors) {
    T_ASSERT(!dt_parses("pkh(@0)"));
    T_ASSERT(!dt_parses("pkh(@0**)"));
    T_ASSERT(!dt_parses("pkh(@a/**)"));
    T_ASSERT(!dt_parses("pkh(@0/*)"));
    T_ASSERT(!dt_parses("pkh(@0/<0;1>)"));
    T_ASSERT(!dt_parses("pkh(@0/<0,1>/*)"));
    T_ASSERT(!dt_parses("pkh(@4294967296/**)"));
    T_ASSERT(!dt_parses("pkh(0/**)"));
}

/* ============================================================ */
/* sortedmulti                                                  */
/* ============================================================ */

TEST(parse_sortedmulti) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("sh(sortedmulti(2,@0/**,@1/**))", &dt), BIP388_OK);
    T_EQ_INT(dt->kind, BIP388_DT_SH);
    T_EQ_INT(dt->u.inner->kind, BIP388_DT_SORTEDMULTI);
    T_EQ_UINT(dt->u.inner->u.multi.threshold, 2);
    T_EQ_UINT(dt->u.inner->u.multi.n_keys, 2);
    bip388_dt_free(dt); free(dt);
}

TEST(parse_wsh_sortedmulti) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("wsh(sortedmulti(2,@0/**,@1/**))", &dt), BIP388_OK);
    T_EQ_INT(dt->kind, BIP388_DT_WSH);
    T_EQ_INT(dt->u.inner->kind, BIP388_DT_SORTEDMULTI);
    bip388_dt_free(dt); free(dt);
}

/* ============================================================ */
/* tr(...)                                                      */
/* ============================================================ */

TEST(parse_tr_internal_only) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("tr(@0/**)", &dt), BIP388_OK);
    T_EQ_INT(dt->kind, BIP388_DT_TR);
    T_ASSERT(dt->u.tr.tree == NULL);
    bip388_dt_free(dt); free(dt);
}

TEST(parse_tr_one_leaf) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("tr(@0/**,pkh(@1/**))", &dt), BIP388_OK);
    T_EQ_INT(dt->kind, BIP388_DT_TR);
    T_ASSERT(dt->u.tr.tree != NULL);
    T_EQ_INT(dt->u.tr.tree->kind, BIP388_TT_SCRIPT);
    T_EQ_INT(dt->u.tr.tree->u.script->kind, BIP388_DT_PKH);
    bip388_dt_free(dt); free(dt);
}

TEST(parse_tr_branch_with_derivations) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})", &dt), BIP388_OK);
    T_EQ_INT(dt->kind, BIP388_DT_TR);
    T_EQ_INT(dt->u.tr.key.type, BIP388_KE_PLAIN);
    T_EQ_UINT(dt->u.tr.key.num1, 2);
    T_EQ_UINT(dt->u.tr.key.num2, 1);
    T_EQ_INT(dt->u.tr.tree->kind, BIP388_TT_BRANCH);
    bip388_dt_free(dt); free(dt);
}

TEST(parse_tr_errors) {
    T_ASSERT(!dt_parses("tr(@0/**,)"));
    T_ASSERT(!dt_parses("tr(pkh(@0/**))"));
    T_ASSERT(!dt_parses("tr(@0)"));
    T_ASSERT(!dt_parses("tr(@0/*)"));
    T_ASSERT(!dt_parses("tr(@0/*/0)"));
}

/* ============================================================ */
/* Other valid descriptors                                      */
/* ============================================================ */

TEST(valid_descriptors_succeed) {
    static const char *cases[] = {
        "sln:older(12960)",
        "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        "wsh(sortedmulti(2,@0/**,@1/**))",
        "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
        "wsh(c:pk_k(@0/**))",
        "wsh(or_d(pk(@0/**),pkh(@1/**)))",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        T_ASSERT(dt_parses(cases[i]));
    }
}

/* ============================================================ */
/* Placeholders iterator                                        */
/* ============================================================ */

static void check_placeholders(const char *desc, const char **expected, size_t n_expected) {
    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str(desc, &dt), BIP388_OK);
    bip388_placeholder_t *phs = NULL;
    size_t n = 0;
    T_EQ_INT(bip388_dt_placeholders(dt, &phs, &n), BIP388_OK);
    T_EQ_UINT(n, n_expected);
    for (size_t i = 0; i < n; ++i) {
        char buf[64];
        snprintf(buf, sizeof(buf), "@%u/<%u;%u>/*",
                 phs[i].ke->u.plain_index, phs[i].ke->num1, phs[i].ke->num2);
        T_EQ_STR(buf, expected[i]);
    }
    bip388_dt_placeholders_free(phs);
    bip388_dt_free(dt); free(dt);
}

TEST(placeholders_iterator) {
    {
        bip388_dt_t *dt = NULL;
        T_EQ_INT(bip388_dt_from_str("0", &dt), BIP388_OK);
        bip388_placeholder_t *phs = NULL;
        size_t n = 0;
        T_EQ_INT(bip388_dt_placeholders(dt, &phs, &n), BIP388_OK);
        T_EQ_UINT(n, 0);
        bip388_dt_placeholders_free(phs);
        bip388_dt_free(dt); free(dt);
    }
    {
        const char *e[] = {"@0/<0;1>/*"};
        check_placeholders("pkh(@0/**)", e, 1);
    }
    {
        const char *e[] = {"@0/<11;67>/*"};
        check_placeholders("wpkh(@0/<11;67>/*)", e, 1);
    }
    {
        const char *e[] = {"@0/<0;1>/*"};
        check_placeholders("tr(@0/**)", e, 1);
    }
    {
        const char *e[] = {"@4/<3;7>/*", "@0/<0;1>/*", "@3/<0;1>/*", "@5/<99;101>/*", "@1/<0;1>/*"};
        check_placeholders(
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            e, 5);
    }
    {
        const char *e[] = {"@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*"};
        check_placeholders(
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
            e, 5);
    }
}

/* ============================================================ */
/* Display round-trip                                           */
/* ============================================================ */

static void roundtrip(const char *s) {
    bip388_dt_t *dt = NULL;
    bip388_err_t err = bip388_dt_from_str(s, &dt);
    T_EQ_INT(err, BIP388_OK);
    size_t need = bip388_dt_format(dt, NULL, 0);
    char buf[2048];
    T_ASSERT(need + 1 <= sizeof(buf));
    bip388_dt_format(dt, buf, sizeof(buf));
    T_EQ_STR(buf, s);
    bip388_dt_free(dt); free(dt);
}

TEST(display_roundtrip) {
    static const char *cases[] = {
        "0", "1",
        "pkh(@0/**)", "wpkh(@0/**)", "wpkh(@0/<11;67>/*)",
        "wsh(sortedmulti(2,@0/**,@1/**))",
        "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
        "wsh(c:pk_k(@0/**))",
        "wsh(or_d(pk(@0/**),pkh(@1/**)))",
        "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        "sln:older(12960)",
        "tr(@0/**)", "tr(@0/**,pkh(@1/**))",
        "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
        "after(12345)", "older(65535)",
        "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
        "ripemd160(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
        "hash256(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
        "hash160(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
        "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
        "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
        "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) roundtrip(cases[i]);
}

/* ============================================================ */
/* Musig                                                        */
/* ============================================================ */

TEST(musig_inside_tr_parses) {
    T_ASSERT(dt_parses("tr(musig(@0,@1)/**)"));
    T_ASSERT(dt_parses("tr(@0/**,pk(musig(@1,@2)/**))"));
    T_ASSERT(dt_parses("tr(musig(@0,@1,@2)/**)"));
    T_ASSERT(dt_parses("tr(musig(@0,@1)/<3;4>/*)"));
}

TEST(musig_outside_tr_rejected) {
    static const char *cases[] = {
        "wpkh(musig(@0,@1)/**)",
        "pkh(musig(@0,@1)/**)",
        "wsh(sortedmulti(2,musig(@0,@1)/**,@2/**))",
        "sh(pk(musig(@0,@1)/**))",
        "wsh(pk(musig(@0,@1)/**))",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        T_ASSERT(dt_error(cases[i], BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    }
}

TEST(musig_nested_not_allowed) {
    T_ASSERT(!dt_parses("tr(musig(musig(@0,@1),@2)/**)"));
}

TEST(musig_display_roundtrip) {
    static const char *cases[] = {
        "tr(musig(@0,@1)/**)",
        "tr(musig(@0,@1)/<3;4>/*)",
        "tr(musig(@0,@1,@2)/**)",
        "tr(@0/**,pk(musig(@1,@2)/**))",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) roundtrip(cases[i]);
}

/* ============================================================ */
/* Script context                                               */
/* ============================================================ */

TEST(sh_only_top_level) {
    T_ASSERT(dt_parses("sh(wsh(sortedmulti(2,@0/**,@1/**)))"));
    T_ASSERT(dt_parses("sh(sortedmulti(2,@0/**,@1/**))"));
    T_ASSERT(dt_error("wsh(sh(pk(@0/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("sh(sh(pk(@0/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("tr(@0/**,sh(pk(@1/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
}

TEST(wsh_only_top_level_or_inside_sh) {
    T_ASSERT(dt_parses("wsh(sortedmulti(2,@0/**,@1/**))"));
    T_ASSERT(dt_parses("sh(wsh(sortedmulti(2,@0/**,@1/**)))"));
    T_ASSERT(dt_error("wsh(wsh(pk(@0/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("tr(@0/**,wsh(pk(@1/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("sh(wsh(wsh(pk(@0/**))))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
}

TEST(tr_only_top_level) {
    T_ASSERT(dt_parses("tr(@0/**)"));
    T_ASSERT(dt_parses("tr(@0/**,pk(@1/**))"));
    T_ASSERT(dt_error("sh(tr(@0/**))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("wsh(tr(@0/**))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
    T_ASSERT(dt_error("tr(@0/**,tr(@1/**))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
}

TEST(musig_not_allowed_in_wsh_inside_tr) {
    T_ASSERT(dt_error("tr(@0/**,wsh(pk(musig(@1,@2)/**)))", BIP388_ERR_INVALID_SCRIPT_CONTEXT));
}

/* ============================================================ */
/* Threshold rejections                                         */
/* ============================================================ */

TEST(reject_zero_threshold) {
    static const char *cases[] = {
        "wsh(multi(0,@0/**,@1/**))",
        "wsh(sortedmulti(0,@0/**,@1/**))",
        "tr(@0/**,multi_a(0,@1/**,@2/**))",
        "tr(@0/**,sortedmulti_a(0,@1/**,@2/**))",
        "wsh(thresh(0,pk(@0/**)))",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        T_ASSERT(dt_error(cases[i], BIP388_ERR_INVALID_MULTISIG_QUORUM));
    }
}

TEST(reject_threshold_exceeds_keys) {
    static const char *cases[] = {
        "wsh(multi(3,@0/**,@1/**))",
        "wsh(sortedmulti(3,@0/**,@1/**))",
        "tr(@0/**,multi_a(3,@1/**,@2/**))",
        "tr(@0/**,sortedmulti_a(3,@1/**,@2/**))",
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
        T_ASSERT(dt_error(cases[i], BIP388_ERR_INVALID_MULTISIG_QUORUM));
    }
}

TEST(reject_duplicate_musig_keys) {
    T_ASSERT(dt_error("tr(musig(@0,@0)/**)", BIP388_ERR_INVALID_KEY));
    T_ASSERT(dt_error("tr(@0/**,pk(musig(@1,@1)/**))", BIP388_ERR_INVALID_KEY));
    T_ASSERT(dt_error("tr(musig(@0,@1,@0)/**)", BIP388_ERR_INVALID_KEY));
}

TEST(reject_too_many_keys_multi) {
    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "wsh(multi(2");
    for (int i = 0; i < 21; ++i) n += snprintf(buf + n, sizeof(buf) - n, ",@%d/**", i);
    n += snprintf(buf + n, sizeof(buf) - n, "))");
    T_ASSERT(dt_error(buf, BIP388_ERR_TOO_MANY_KEYS));

    n = snprintf(buf, sizeof(buf), "wsh(multi(2");
    for (int i = 0; i < 20; ++i) n += snprintf(buf + n, sizeof(buf) - n, ",@%d/**", i);
    n += snprintf(buf + n, sizeof(buf) - n, "))");
    T_ASSERT(dt_parses(buf));
}

TEST(accept_more_than_20_keys_multi_a) {
    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "tr(@0/**,multi_a(2");
    for (int i = 1; i <= 50; ++i) n += snprintf(buf + n, sizeof(buf) - n, ",@%d/**", i);
    n += snprintf(buf + n, sizeof(buf) - n, "))");
    T_ASSERT(dt_parses(buf));
}

/* ============================================================ */
/* Nesting limit                                                */
/* ============================================================ */

TEST(nesting_wrapper_chain_ok) {
    char buf[2048];
    for (int i = 0; i < 1000; ++i) buf[i] = 'j';
    strcpy(buf + 1000, ":0");
    T_ASSERT(dt_parses(buf));
}

TEST(nesting_andor_overflow) {
    size_t depth = BIP388_MAX_PARSE_DEPTH + 5;
    size_t total = depth * 8 + 1 + depth * 3 + 1;
    char *buf = (char *)malloc(total + 1);
    char *p = buf;
    for (size_t i = 0; i < depth; ++i) { memcpy(p, "andor(0,", 8); p += 8; }
    *p++ = '0';
    for (size_t i = 0; i < depth; ++i) { memcpy(p, ",0)", 3); p += 3; }
    *p = '\0';
    T_ASSERT(dt_error(buf, BIP388_ERR_NESTING_TOO_DEEP));
    free(buf);
}

TEST(nesting_taptree_braces_overflow) {
    size_t depth = BIP388_MAX_PARSE_DEPTH + 5;
    char *buf = (char *)malloc(depth * 12 + 100);
    char *p = buf;
    p += sprintf(p, "tr(@0/**,");
    for (size_t i = 0; i < depth; ++i) *p++ = '{';
    p += sprintf(p, "pk(@1/**)");
    for (size_t i = 0; i < depth; ++i) { memcpy(p, ",pk(@2/**)}", 11); p += 11; }
    *p++ = ')';
    *p = '\0';
    T_ASSERT(dt_error(buf, BIP388_ERR_NESTING_TOO_DEEP));
    free(buf);
}

TEST(nesting_taptree_within_limit) {
    size_t depth = BIP388_MAX_PARSE_DEPTH - 4;
    char *buf = (char *)malloc(depth * 12 + 100);
    char *p = buf;
    p += sprintf(p, "tr(@0/**,");
    for (size_t i = 0; i < depth; ++i) *p++ = '{';
    p += sprintf(p, "pk(@1/**)");
    for (size_t i = 0; i < depth; ++i) { memcpy(p, ",pk(@2/**)}", 11); p += 11; }
    *p++ = ')';
    *p = '\0';
    T_ASSERT(dt_parses(buf));
    free(buf);
}

/* ============================================================ */
/* to_descriptor                                                */
/* ============================================================ */

TEST(to_descriptor_exact_output) {
    bip388_key_info_t keys[2] = {0};
    T_EQ_INT(bip388_key_info_parse(XPUB_C, &keys[0]), BIP388_OK);
    T_EQ_INT(bip388_key_info_parse(XPUB_C, &keys[1]), BIP388_OK);

    bip388_dt_t *dt = NULL;
    T_EQ_INT(bip388_dt_from_str("wsh(sortedmulti(2,@0/**,@1/**))", &dt), BIP388_OK);
    char out[1024];
    size_t outlen = 0;
    T_EQ_INT(bip388_dt_to_descriptor(dt, keys, 2, false, 7, out, sizeof(out), &outlen), BIP388_OK);
    char expected[1024];
    snprintf(expected, sizeof(expected), "wsh(sortedmulti(2,%s/0/7,%s/0/7))", XPUB_C, XPUB_C);
    T_EQ_STR(out, expected);
    bip388_dt_free(dt); free(dt);

    T_EQ_INT(bip388_dt_from_str("wsh(thresh(1,pk(@0/**),s:pk(@1/**)))", &dt), BIP388_OK);
    T_EQ_INT(bip388_dt_to_descriptor(dt, keys, 2, true, 3, out, sizeof(out), &outlen), BIP388_OK);
    snprintf(expected, sizeof(expected), "wsh(thresh(1,pk(%s/1/3),s:pk(%s/1/3)))", XPUB_C, XPUB_C);
    T_EQ_STR(out, expected);
    bip388_dt_free(dt); free(dt);

    bip388_key_info_free(&keys[0]);
    bip388_key_info_free(&keys[1]);
}
