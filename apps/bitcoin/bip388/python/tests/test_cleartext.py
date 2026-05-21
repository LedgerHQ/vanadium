"""Port of `src/cleartext/mod.rs` tests + the shared `test_vectors.toml`.

The `from_cleartext_roundtrip` test from the Rust suite is intentionally
omitted: the reverse direction lives in the `cleartext-decode` feature
and is not part of this Python port.
"""

import tomllib
import unittest
from pathlib import Path

from bip388 import DescriptorTemplate, classify, confusion_score, to_cleartext
from bip388.cleartext import TAPLEAF_SPECS, TOP_LEVEL_SPECS

# Tests load the same TOML the Rust crate uses, kept under the parent
# Cargo crate so both implementations stay in sync.
TEST_VECTORS_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "cleartext"
    / "specs"
    / "test_vectors.toml"
)


def _load_vectors():
    with open(TEST_VECTORS_PATH, "rb") as f:
        data = tomllib.load(f)
    return data["vector"]


class TestVectorsConfusionScore(unittest.TestCase):
    def test_all(self):
        for v in _load_vectors():
            expected = v.get("confusion_score")
            if expected is None:
                continue
            with self.subTest(template=v["template"]):
                dt = DescriptorTemplate.from_str(v["template"])
                self.assertEqual(
                    confusion_score(dt),
                    expected,
                    f"confusion_score mismatch for {v['template']!r}",
                )


class TestVectorsToCleartext(unittest.TestCase):
    def test_all(self):
        for v in _load_vectors():
            if "cleartext" not in v or "has_cleartext" not in v:
                continue
            with self.subTest(template=v["template"]):
                dt = DescriptorTemplate.from_str(v["template"])
                actual_ct, actual_hct = to_cleartext(dt)
                self.assertEqual(actual_ct, v["cleartext"])
                self.assertEqual(actual_hct, v["has_cleartext"])


class TestVectorsHasCleartextOnly(unittest.TestCase):
    def test_all(self):
        for v in _load_vectors():
            if "cleartext" in v:
                continue
            expected = v.get("has_cleartext")
            if expected is None:
                continue
            with self.subTest(template=v["template"]):
                dt = DescriptorTemplate.from_str(v["template"])
                _, actual_hct = to_cleartext(dt)
                self.assertEqual(actual_hct, expected)


class TestSpecShapeUniqueness(unittest.TestCase):
    """Each spec entry's cleartext "shape" (literals with dynamic fields
    replaced by a sentinel) must be unique within its section, otherwise
    two entries would be indistinguishable."""

    @staticmethod
    def _shape(tokens):
        PLACEHOLDER = "§"  # '§'
        parts = []
        for tok in tokens:
            parts.append(tok.text if tok.is_literal else PLACEHOLDER)
        return "".join(parts)

    def _check_unique(self, entries, label):
        seen = {}
        for e in entries:
            sig = self._shape(e.cleartext_tokens)
            if sig in seen:
                self.fail(
                    f"{label} entries {seen[sig]!r} and {e.name!r} have the same shape: {sig!r}"
                )
            seen[sig] = e.name

    def test_top_level(self):
        self._check_unique(TOP_LEVEL_SPECS, "TOP_LEVEL_SPECS")

    def test_tapleaf(self):
        self._check_unique(TAPLEAF_SPECS, "TAPLEAF_SPECS")


class TestMusigClassifyPreservesDerivations(unittest.TestCase):
    def test_internal_key_with_custom_derivation(self):
        dt = DescriptorTemplate.from_str("tr(musig(@0,@1)/<2;3>/*,pk(@2/**))")
        cls = classify(dt)
        self.assertEqual(cls.name, "TaprootMusig")
        self.assertEqual(cls.fields["threshold"], 2)
        keys = cls.fields["keys"]
        self.assertEqual(len(keys), 2)
        for k in keys:
            self.assertTrue(k.is_plain())
            self.assertEqual(k.num1, 2)
            self.assertEqual(k.num2, 3)
        self.assertEqual(keys[0].plain_key_index(), 0)
        self.assertEqual(keys[1].plain_key_index(), 1)
        self.assertEqual(len(cls.fields["leaves"]), 1)

    def test_tapleaf_musig_custom_derivation(self):
        dt = DescriptorTemplate.from_str("tr(@0/**,pk(musig(@1,@2)/<4;5>/*))")
        cls = classify(dt)
        self.assertEqual(cls.name, "Taproot")
        leaves = cls.fields["leaves"]
        self.assertEqual(len(leaves), 1)
        self.assertEqual(leaves[0].name, "Multisig")
        self.assertEqual(leaves[0].fields["threshold"], 2)
        for k in leaves[0].fields["keys"]:
            self.assertEqual(k.num1, 4)
            self.assertEqual(k.num2, 5)

    def test_standard_derivation(self):
        dt = DescriptorTemplate.from_str("tr(musig(@0,@1)/**)")
        cls = classify(dt)
        self.assertEqual(cls.name, "TaprootMusig")
        self.assertEqual(cls.fields["threshold"], 2)
        for k in cls.fields["keys"]:
            self.assertEqual(k.num1, 0)
            self.assertEqual(k.num2, 1)
        self.assertEqual(cls.fields["leaves"], [])


if __name__ == "__main__":
    unittest.main()
