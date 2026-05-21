"""BIP-388 wallet policies & descriptor templates (Python port).

Mirrors the Rust ``bip388`` crate without the ``cleartext-decode``
feature. See the parent Cargo crate for the authoritative spec.
"""

from .descriptor import (
    HARDENED_INDEX,
    MAX_BIP32_DERIVATION_PATH_LEN,
    MAX_KEYS_MULTI,
    MAX_KEYS_MULTI_A,
    MAX_OLDER_AFTER,
    MAX_PARSE_DEPTH,
    MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN,
    MAX_SERIALIZED_KEY_COUNT,
    DescriptorTemplate,
    KeyExpression,
    KeyInformation,
    KeyOrigin,
    ParseContext,
    ParseError,
    ParseErrorKind,
    TapTree,
    format_child_number,
    parse_child_number,
    to_descriptor,
)
from .wallet_policy import DeserializeError, SegwitVersion, WalletPolicy
from .xpub import Xpub
from . import cleartext
from .cleartext import (
    MAX_CONFUSION_SCORE,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
    classify,
    classify_as_tapleaf,
    confusion_score,
    to_cleartext,
)
from .time_fmt import format_seconds, format_utc_date

__all__ = [
    # descriptor
    "HARDENED_INDEX",
    "MAX_BIP32_DERIVATION_PATH_LEN",
    "MAX_KEYS_MULTI",
    "MAX_KEYS_MULTI_A",
    "MAX_OLDER_AFTER",
    "MAX_PARSE_DEPTH",
    "MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN",
    "MAX_SERIALIZED_KEY_COUNT",
    "DescriptorTemplate",
    "KeyExpression",
    "KeyInformation",
    "KeyOrigin",
    "ParseContext",
    "ParseError",
    "ParseErrorKind",
    "TapTree",
    "format_child_number",
    "parse_child_number",
    "to_descriptor",
    # wallet_policy
    "DeserializeError",
    "SegwitVersion",
    "WalletPolicy",
    # xpub
    "Xpub",
    # cleartext
    "cleartext",
    "MAX_CONFUSION_SCORE",
    "SEQUENCE_LOCKTIME_TYPE_FLAG",
    "classify",
    "classify_as_tapleaf",
    "confusion_score",
    "to_cleartext",
    # time
    "format_seconds",
    "format_utc_date",
]
