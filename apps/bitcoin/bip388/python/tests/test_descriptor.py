"""Port of `src/lib.rs` unit tests."""

import unittest

from bip388 import (
    HARDENED_INDEX,
    DescriptorTemplate,
    KeyExpression,
    KeyInformation,
    KeyOrigin,
    MAX_PARSE_DEPTH,
    ParseContext,
    ParseError,
    ParseErrorKind,
    TapTree,
    to_descriptor,
)
from bip388.descriptor import (
    _parse_descriptor,
    _parse_derivation_step_number,
    _parse_key_expression,
    _parse_thresh,
    _parse_threshold_kp_fragment,
    _parse_tr,
)


H = HARDENED_INDEX
MAX_STEP = "2147483647"
MAX_STEP_H = "2147483647'"


class TestDerivationStep(unittest.TestCase):
    def test_success(self):
        cases = [
            ("0", ("", 0)),
            ("0'", ("", H)),
            ("1", ("", 1)),
            ("1'", ("", 1 + H)),
            (MAX_STEP, ("", H - 1)),
            (MAX_STEP_H, ("", H - 1 + H)),
            ("5h", ("h", 5)),
            ("5H", ("H", 5)),
        ]
        for input_, expected in cases:
            with self.subTest(input=input_):
                self.assertEqual(_parse_derivation_step_number(input_), expected)

    def test_errors(self):
        for s in ("", "a", "H", "H'"):
            with self.subTest(input=s):
                with self.assertRaises(ParseError):
                    _parse_derivation_step_number(s)


def _origin(fpr: int, path):
    return KeyOrigin(fingerprint=fpr, derivation_path=tuple(path))


class TestKeyOrigin(unittest.TestCase):
    def test_success(self):
        cases = [
            ("012345af/0'/1'/3", _origin(0x012345AF, [0 + H, 1 + H, 3])),
            (
                "012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89",
                _origin(
                    0x012345AF,
                    [2147483647 + H, 1 + H, 3, 6, 7, 42, 12, 54, 23, 56, 89],
                ),
            ),
            ("012345af", _origin(0x012345AF, [])),
        ]
        for input_, expected in cases:
            with self.subTest(input=input_):
                self.assertEqual(KeyOrigin.parse(input_), expected)

    def test_errors(self):
        for s in (
            "[01234567/0'/1'/3]",
            "0123456/0'/1'/3",
            "012345678/0'/1'/3",
            "012345ag/0'/1'/2147483648",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError):
                    KeyOrigin.parse(s)


class TestKeyExpression(unittest.TestCase):
    def test_success(self):
        cases = [
            ("@0/**", KeyExpression.plain(0, 0, 1)),
            ("@4294967295/**", KeyExpression.plain(4294967295, 0, 1)),
            ("@1/<0;1>/*", KeyExpression.plain(1, 0, 1)),
            ("@2/<3;4>/*", KeyExpression.plain(2, 3, 4)),
            ("@3/<1;9>/*", KeyExpression.plain(3, 1, 9)),
        ]
        for input_, expected in cases:
            with self.subTest(input=input_):
                rest, ke = _parse_key_expression(input_, ParseContext.TopLevel)
                self.assertEqual(rest, "")
                self.assertEqual(ke, expected)

    def test_errors(self):
        for s in (
            "@0",
            "@0**",
            "@a/**",
            "@0/*",
            "@0/<0;1>",
            "@0/<0,1>/*",
            "@4294967296/**",
            "0/**",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError):
                    _parse_key_expression(s, ParseContext.TopLevel)


class TestSortedmulti(unittest.TestCase):
    def test_sortedmulti(self):
        rest, dt = _parse_threshold_kp_fragment(
            "sortedmulti(2,@0/**,@1/**)",
            "sortedmulti",
            "Sortedmulti",
            ParseContext.TopLevel,
            20,
        )
        self.assertEqual(rest, "")
        self.assertEqual(
            dt,
            DescriptorTemplate(
                kind="Sortedmulti",
                args=(
                    2,
                    [KeyExpression.plain(0, 0, 1), KeyExpression.plain(1, 0, 1)],
                ),
            ),
        )

    def test_wsh_sortedmulti(self):
        dt = DescriptorTemplate.from_str("wsh(sortedmulti(2,@0/**,@1/**))")
        self.assertEqual(
            dt,
            DescriptorTemplate(
                kind="Wsh",
                args=(
                    DescriptorTemplate(
                        kind="Sortedmulti",
                        args=(
                            2,
                            [
                                KeyExpression.plain(0, 0, 1),
                                KeyExpression.plain(1, 0, 1),
                            ],
                        ),
                    ),
                ),
            ),
        )


class TestParseTr(unittest.TestCase):
    def test_internal_only(self):
        rest, dt = _parse_tr("tr(@0/**)", 0)
        self.assertEqual(rest, "")
        self.assertEqual(
            dt,
            DescriptorTemplate(
                kind="Tr", args=(KeyExpression.plain(0, 0, 1), None)
            ),
        )

    def test_one_leaf(self):
        rest, dt = _parse_tr("tr(@0/**,pkh(@1/**))", 0)
        self.assertEqual(rest, "")
        self.assertEqual(
            dt,
            DescriptorTemplate(
                kind="Tr",
                args=(
                    KeyExpression.plain(0, 0, 1),
                    TapTree.script(
                        DescriptorTemplate(
                            kind="Pkh", args=(KeyExpression.plain(1, 0, 1),)
                        )
                    ),
                ),
            ),
        )

    def test_branch_with_explicit_derivations(self):
        rest, dt = _parse_tr("tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})", 0)
        self.assertEqual(rest, "")
        self.assertEqual(
            dt,
            DescriptorTemplate(
                kind="Tr",
                args=(
                    KeyExpression.plain(0, 2, 1),
                    TapTree.branch(
                        TapTree.script(
                            DescriptorTemplate(
                                kind="Pkh", args=(KeyExpression.plain(1, 2, 7),)
                            )
                        ),
                        TapTree.script(
                            DescriptorTemplate(
                                kind="Pk", args=(KeyExpression.plain(2, 0, 1),)
                            )
                        ),
                    ),
                ),
            ),
        )

    def test_errors(self):
        for s in ("tr(@0/**,)", "tr(pkh(@0/**))", "tr(@0))", "tr(@0/*))", "tr(@0/*/0)"):
            with self.subTest(input=s):
                with self.assertRaises(ParseError):
                    _parse_tr(s, 0)


class TestValidDescriptorTemplates(unittest.TestCase):
    def test_success_cases(self):
        rest, _ = _parse_descriptor("sln:older(12960)", ParseContext.TopLevel, 0)
        self.assertEqual(rest, "")
        rest, _ = _parse_thresh(
            "thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960))",
            ParseContext.TopLevel,
            0,
        )
        self.assertEqual(rest, "")
        for s in (
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        ):
            with self.subTest(input=s):
                DescriptorTemplate.from_str(s)


def _koi(s: str) -> KeyInformation:
    return KeyInformation.parse(s)


XPUB_A = (
    "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"
)
XPUB_B = (
    "tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"
)
XPUB_C = (
    "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
)


class TestPlaceholdersIterator(unittest.TestCase):
    def _format(self, kp):
        return f"@{kp.plain_key_index()}/<{kp.num1};{kp.num2}>/*"

    def test_cases(self):
        cases = [
            ("0", []),
            ("after(12345)", []),
            ("pkh(@0/**)", ["@0/<0;1>/*"]),
            ("wpkh(@0/<11;67>/*)", ["@0/<11;67>/*"]),
            ("tr(@0/**)", ["@0/<0;1>/*"]),
            (
                "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
                ["@4/<3;7>/*", "@0/<0;1>/*", "@3/<0;1>/*", "@5/<99;101>/*", "@1/<0;1>/*"],
            ),
            (
                "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
                ["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*"],
            ),
        ]
        for descriptor, expected in cases:
            with self.subTest(descriptor=descriptor):
                dt = DescriptorTemplate.from_str(descriptor)
                got = [self._format(k) for k, _ in dt.placeholders()]
                self.assertEqual(got, expected)


class TestDisplayRoundtrip(unittest.TestCase):
    def test_roundtrip(self):
        cases = [
            "0",
            "1",
            "pkh(@0/**)",
            "wpkh(@0/**)",
            "wpkh(@0/<11;67>/*)",
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
            "sln:older(12960)",
            "tr(@0/**)",
            "tr(@0/**,pkh(@1/**))",
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),pk(@2/**)})",
            "after(12345)",
            "older(65535)",
            "sha256(" + "aa" * 32 + ")",
            "ripemd160(" + "aa" * 20 + ")",
            "hash256(" + "bb" * 32 + ")",
            "hash160(" + "bb" * 20 + ")",
            "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        ]
        for s in cases:
            with self.subTest(input=s):
                parsed = DescriptorTemplate.from_str(s)
                self.assertEqual(str(parsed), s)


class TestMusig(unittest.TestCase):
    def test_inside_tr_parses(self):
        for s in (
            "tr(musig(@0,@1)/**)",
            "tr(@0/**,pk(musig(@1,@2)/**))",
            "tr(musig(@0,@1,@2)/**)",
            "tr(musig(@0,@1)/<3;4>/*)",
        ):
            with self.subTest(input=s):
                DescriptorTemplate.from_str(s)

    def test_outside_tr_rejected(self):
        for s in (
            "wpkh(musig(@0,@1)/**)",
            "pkh(musig(@0,@1)/**)",
            "wsh(sortedmulti(2,musig(@0,@1)/**,@2/**))",
            "sh(pk(musig(@0,@1)/**))",
            "wsh(pk(musig(@0,@1)/**))",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidScriptContext)

    def test_nested_not_allowed(self):
        with self.assertRaises(ParseError):
            DescriptorTemplate.from_str("tr(musig(musig(@0,@1),@2)/**)")

    def test_display_roundtrip(self):
        for s in (
            "tr(musig(@0,@1)/**)",
            "tr(musig(@0,@1)/<3;4>/*)",
            "tr(musig(@0,@1,@2)/**)",
            "tr(@0/**,pk(musig(@1,@2)/**))",
        ):
            with self.subTest(input=s):
                parsed = DescriptorTemplate.from_str(s)
                self.assertEqual(str(parsed), s)


class TestScriptContext(unittest.TestCase):
    def test_sh_only_top_level(self):
        DescriptorTemplate.from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))")
        DescriptorTemplate.from_str("sh(sortedmulti(2,@0/**,@1/**))")
        for s in (
            "wsh(sh(pk(@0/**)))",
            "sh(sh(pk(@0/**)))",
            "tr(@0/**,sh(pk(@1/**)))",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidScriptContext)

    def test_wsh_only_top_level_or_inside_sh(self):
        DescriptorTemplate.from_str("wsh(sortedmulti(2,@0/**,@1/**))")
        DescriptorTemplate.from_str("sh(wsh(sortedmulti(2,@0/**,@1/**)))")
        for s in (
            "wsh(wsh(pk(@0/**)))",
            "tr(@0/**,wsh(pk(@1/**)))",
            "sh(wsh(wsh(pk(@0/**))))",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidScriptContext)

    def test_tr_only_top_level(self):
        DescriptorTemplate.from_str("tr(@0/**)")
        DescriptorTemplate.from_str("tr(@0/**,pk(@1/**))")
        for s in ("sh(tr(@0/**))", "wsh(tr(@0/**))", "tr(@0/**,tr(@1/**))"):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidScriptContext)

    def test_musig_not_allowed_in_wsh_inside_tr(self):
        with self.assertRaises(ParseError) as cm:
            DescriptorTemplate.from_str("tr(@0/**,wsh(pk(musig(@1,@2)/**)))")
        self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidScriptContext)


class TestThresholdRejections(unittest.TestCase):
    def test_zero_threshold(self):
        for s in (
            "wsh(multi(0,@0/**,@1/**))",
            "wsh(sortedmulti(0,@0/**,@1/**))",
            "tr(@0/**,multi_a(0,@1/**,@2/**))",
            "tr(@0/**,sortedmulti_a(0,@1/**,@2/**))",
            "wsh(thresh(0,pk(@0/**)))",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidMultisigQuorum)

    def test_threshold_exceeds_keys(self):
        for s in (
            "wsh(multi(3,@0/**,@1/**))",
            "wsh(sortedmulti(3,@0/**,@1/**))",
            "tr(@0/**,multi_a(3,@1/**,@2/**))",
            "tr(@0/**,sortedmulti_a(3,@1/**,@2/**))",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidMultisigQuorum)

    def test_duplicate_musig_keys(self):
        for s in (
            "tr(musig(@0,@0)/**)",
            "tr(@0/**,pk(musig(@1,@1)/**))",
            "tr(musig(@0,@1,@0)/**)",
        ):
            with self.subTest(input=s):
                with self.assertRaises(ParseError) as cm:
                    DescriptorTemplate.from_str(s)
                self.assertEqual(cm.exception.kind, ParseErrorKind.InvalidKey)

    def test_too_many_keys_multi(self):
        s = "wsh(multi(2"
        for i in range(21):
            s += f",@{i}/**"
        s += "))"
        with self.assertRaises(ParseError) as cm:
            DescriptorTemplate.from_str(s)
        self.assertEqual(cm.exception.kind, ParseErrorKind.TooManyKeys)

        s = "wsh(multi(2"
        for i in range(20):
            s += f",@{i}/**"
        s += "))"
        DescriptorTemplate.from_str(s)

    def test_more_than_20_keys_multi_a(self):
        s = "tr(@0/**,multi_a(2"
        for i in range(1, 51):
            s += f",@{i}/**"
        s += "))"
        DescriptorTemplate.from_str(s)


class TestNestingLimit(unittest.TestCase):
    def test_wrapper_chain_ok(self):
        s = "j" * 1000 + ":0"
        DescriptorTemplate.from_str(s)

    def test_andor_overflow(self):
        s = "andor(0," * (MAX_PARSE_DEPTH + 5) + "0" + ",0)" * (MAX_PARSE_DEPTH + 5)
        with self.assertRaises(ParseError) as cm:
            DescriptorTemplate.from_str(s)
        self.assertEqual(cm.exception.kind, ParseErrorKind.NestingTooDeep)

    def test_taptree_braces_overflow(self):
        s = "tr(@0/**," + "{" * (MAX_PARSE_DEPTH + 5)
        s += "pk(@1/**)" + ",pk(@2/**)}" * (MAX_PARSE_DEPTH + 5) + ")"
        with self.assertRaises(ParseError) as cm:
            DescriptorTemplate.from_str(s)
        self.assertEqual(cm.exception.kind, ParseErrorKind.NestingTooDeep)

    def test_taptree_within_limit(self):
        inner_depth = MAX_PARSE_DEPTH - 4
        s = "tr(@0/**," + "{" * inner_depth
        s += "pk(@1/**)" + ",pk(@2/**)}" * inner_depth + ")"
        DescriptorTemplate.from_str(s)


class TestToDescriptor(unittest.TestCase):
    def test_exact_output(self):
        keys = [KeyInformation.parse(XPUB_C), KeyInformation.parse(XPUB_C)]
        dt = DescriptorTemplate.from_str("wsh(sortedmulti(2,@0/**,@1/**))")
        out = to_descriptor(dt, keys, is_change=False, address_index=7)
        self.assertEqual(out, f"wsh(sortedmulti(2,{XPUB_C}/0/7,{XPUB_C}/0/7))")

        dt = DescriptorTemplate.from_str("wsh(thresh(1,pk(@0/**),s:pk(@1/**)))")
        out = to_descriptor(dt, keys, is_change=True, address_index=3)
        self.assertEqual(
            out, f"wsh(thresh(1,pk({XPUB_C}/1/3),s:pk({XPUB_C}/1/3)))"
        )


if __name__ == "__main__":
    unittest.main()
