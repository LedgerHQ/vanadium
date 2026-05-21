"""Port of `WalletPolicy`-related tests from `src/lib.rs`."""

import unittest

from bip388 import (
    DeserializeError,
    KeyInformation,
    MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN,
    MAX_SERIALIZED_KEY_COUNT,
    WalletPolicy,
)
from bip388.wallet_policy import _varint_encode


XPUB_A = (
    "tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"
)
XPUB_B = (
    "tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"
)


class TestWalletPolicyConstruction(unittest.TestCase):
    def test_new(self):
        keys = [
            KeyInformation.parse(f"[76223a6e/48'/1'/0'/1']{XPUB_A}"),
            KeyInformation.parse(f"[f5acc2fd/48'/1'/0'/1']{XPUB_B}"),
        ]
        wp = WalletPolicy.new("sh(wsh(sortedmulti(2,@0/**,@1/**)))", keys)
        self.assertEqual(
            wp.descriptor_template_raw(), "sh(wsh(sortedmulti(2,@0/**,@1/**)))"
        )
        self.assertEqual(wp.key_information(), tuple(keys))


class TestWalletPolicySerialization(unittest.TestCase):
    def test_roundtrip(self):
        keys = [
            KeyInformation.parse(f"[76223a6e/48'/1'/0'/1']{XPUB_A}"),
            KeyInformation.parse(XPUB_B),
        ]
        wp = WalletPolicy.new("sh(wsh(sortedmulti(2,@0/**,@1/**)))", keys)
        encoded = wp.serialize()
        decoded = WalletPolicy.deserialize(encoded)
        self.assertEqual(decoded.descriptor_template_raw(), wp.descriptor_template_raw())
        self.assertEqual(decoded.key_information(), wp.key_information())


class TestWalletPolicyDeserializationLimits(unittest.TestCase):
    def test_oversized_descriptor(self):
        buf = _varint_encode(MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN + 1)
        with self.assertRaises(DeserializeError):
            WalletPolicy.deserialize(buf)

    def test_oversized_key_count(self):
        buf = _varint_encode(0) + _varint_encode(MAX_SERIALIZED_KEY_COUNT + 1)
        with self.assertRaises(DeserializeError):
            WalletPolicy.deserialize(buf)


if __name__ == "__main__":
    unittest.main()
