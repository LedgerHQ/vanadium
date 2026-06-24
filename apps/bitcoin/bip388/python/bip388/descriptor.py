"""BIP-388 descriptor template parsing, display, and rendering.

This is a Python port of the parsing and display logic in
`src/lib.rs` of the Rust `bip388` crate. The descriptor AST is
represented uniformly as :class:`DescriptorTemplate` objects with a
``kind`` tag and a tuple of ``args``; the args layout per kind
mirrors the Rust enum variants.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Iterator, List, Optional, Sequence, Tuple, Union

from .xpub import Xpub

HARDENED_INDEX = 0x80000000
MAX_OLDER_AFTER = 2147483647

MAX_KEYS_MULTI = 20
MAX_KEYS_MULTI_A = 999
MAX_PARSE_DEPTH = 64
MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN = 4096
MAX_SERIALIZED_KEY_COUNT = MAX_KEYS_MULTI_A
MAX_BIP32_DERIVATION_PATH_LEN = 32


class ParseErrorKind(Enum):
    EmptyInput = "EmptyInput"
    TrailingInput = "TrailingInput"
    InvalidSyntax = "InvalidSyntax"
    InvalidHex = "InvalidHex"
    InvalidKey = "InvalidKey"
    NumberOutOfRange = "NumberOutOfRange"
    InvalidLength = "InvalidLength"
    UnrecognizedFragment = "UnrecognizedFragment"
    TooFewKeyExpressions = "TooFewKeyExpressions"
    ThreshExceedsScripts = "ThreshExceedsScripts"
    InvalidKeyIndex = "InvalidKeyIndex"
    InvalidTopLevelPolicy = "InvalidTopLevelPolicy"
    FormatError = "FormatError"
    InvalidScriptContext = "InvalidScriptContext"
    TooManyKeys = "TooManyKeys"
    InvalidMultisigQuorum = "InvalidMultisigQuorum"
    NestingTooDeep = "NestingTooDeep"


class ParseError(Exception):
    def __init__(self, kind: ParseErrorKind):
        self.kind = kind
        super().__init__(kind.value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ParseError) and self.kind == other.kind

    def __hash__(self) -> int:
        return hash(self.kind)


# Convenience aliases so callers can write `ParseError.EmptyInput`.
for _k in ParseErrorKind:
    setattr(ParseError, _k.name, _k)
del _k


class ParseContext(Enum):
    TopLevel = "TopLevel"
    Legacy = "Legacy"
    Segwit = "Segwit"
    WrappedSegwit = "WrappedSegwit"
    Taproot = "Taproot"

    def musig_allowed(self) -> bool:
        return self is ParseContext.Taproot

    def sh_allowed(self) -> bool:
        return self is ParseContext.TopLevel

    def wpkh_allowed(self) -> bool:
        return self in (ParseContext.TopLevel, ParseContext.Legacy)

    def wsh_allowed(self) -> bool:
        return self in (ParseContext.TopLevel, ParseContext.Legacy)

    def tr_allowed(self) -> bool:
        return self is ParseContext.TopLevel


# ---------------------------------------------------------------------------
# ChildNumber helpers (BIP-32 derivation steps as u32 with hardened bit)
# ---------------------------------------------------------------------------


def format_child_number(n: int) -> str:
    if n >= HARDENED_INDEX:
        return f"{n - HARDENED_INDEX}'"
    return str(n)


def parse_child_number(s: str) -> int:
    if s.endswith("'"):
        base = s[:-1]
        if not base.isdigit():
            raise ValueError(f"invalid child number {s!r}")
        n = int(base)
        if n >= HARDENED_INDEX:
            raise ValueError(f"child index out of range {s!r}")
        return n + HARDENED_INDEX
    if not s.isdigit():
        raise ValueError(f"invalid child number {s!r}")
    n = int(s)
    if n >= HARDENED_INDEX:
        raise ValueError(f"child index out of range {s!r}")
    return n


# ---------------------------------------------------------------------------
# KeyOrigin, KeyInformation, KeyExpression
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KeyOrigin:
    fingerprint: int
    derivation_path: Tuple[int, ...]

    def __str__(self) -> str:
        out = [f"{self.fingerprint:08x}"]
        for step in self.derivation_path:
            out.append("/")
            out.append(format_child_number(step))
        return "".join(out)

    @classmethod
    def parse(cls, s: str) -> "KeyOrigin":
        if not s:
            raise ParseError(ParseErrorKind.EmptyInput)
        parts = s.split("/")
        if len(parts[0]) != 8:
            raise ParseError(ParseErrorKind.InvalidLength)
        try:
            fingerprint = int(parts[0], 16)
        except ValueError:
            raise ParseError(ParseErrorKind.InvalidKey)
        if fingerprint < 0 or fingerprint > 0xFFFFFFFF:
            raise ParseError(ParseErrorKind.InvalidKey)
        path: List[int] = []
        for step in parts[1:]:
            try:
                path.append(parse_child_number(step))
            except ValueError:
                raise ParseError(ParseErrorKind.InvalidKey)
        return cls(fingerprint=fingerprint, derivation_path=tuple(path))


@dataclass(frozen=True)
class KeyInformation:
    pubkey: Xpub
    origin_info: Optional[KeyOrigin]

    def __str__(self) -> str:
        if self.origin_info is None:
            return str(self.pubkey)
        return f"[{self.origin_info}]{self.pubkey}"

    @classmethod
    def parse(cls, s: str) -> "KeyInformation":
        if not s:
            raise ParseError(ParseErrorKind.EmptyInput)
        if s.startswith("["):
            end = s.find("]")
            if end < 0:
                raise ParseError(ParseErrorKind.InvalidKey)
            origin = KeyOrigin.parse(s[1:end])
            pubkey_str = s[end + 1 :]
        else:
            origin = None
            pubkey_str = s
        try:
            pubkey = Xpub.from_str(pubkey_str)
        except (ValueError, KeyError):
            raise ParseError(ParseErrorKind.InvalidKey)
        return cls(pubkey=pubkey, origin_info=origin)


@dataclass(frozen=True)
class KeyExpression:
    """A `@i/**`-style placeholder, optionally a `musig(@i,@j,...)`.

    `key_type` is either ``("Plain", index)`` or ``("Musig", (i1, i2, ...))``.
    """

    key_type: Tuple
    num1: int
    num2: int

    @classmethod
    def plain(cls, key_index: int, num1: int, num2: int) -> "KeyExpression":
        return cls(key_type=("Plain", key_index), num1=num1, num2=num2)

    @classmethod
    def musig(cls, key_indices: Sequence[int], num1: int, num2: int) -> "KeyExpression":
        return cls(key_type=("Musig", tuple(key_indices)), num1=num1, num2=num2)

    def is_plain(self) -> bool:
        return self.key_type[0] == "Plain"

    def is_musig(self) -> bool:
        return self.key_type[0] == "Musig"

    def plain_key_index(self) -> Optional[int]:
        if self.is_plain():
            return self.key_type[1]
        return None

    def musig_key_indices(self) -> Optional[Tuple[int, ...]]:
        if self.is_musig():
            return self.key_type[1]
        return None

    def __str__(self) -> str:
        if self.is_plain():
            idx = self.key_type[1]
            if self.num1 == 0 and self.num2 == 1:
                return f"@{idx}/**"
            return f"@{idx}/<{self.num1};{self.num2}>/*"
        indices = self.key_type[1]
        inner = ",".join(f"@{i}" for i in indices)
        if self.num1 == 0 and self.num2 == 1:
            return f"musig({inner})/**"
        return f"musig({inner})/<{self.num1};{self.num2}>/*"


# ---------------------------------------------------------------------------
# Low-level parsing primitives
# ---------------------------------------------------------------------------


def _parse_number_up_to(s: str, max_value: int) -> Tuple[str, int]:
    if not s or not s[0].isdigit():
        raise ParseError(ParseErrorKind.InvalidSyntax)
    if s.startswith("0") and len(s) > 1 and s[1].isdigit():
        raise ParseError(ParseErrorKind.NumberOutOfRange)
    end = 0
    while end < len(s) and s[end].isdigit():
        end += 1
    n = int(s[:end])
    if n > max_value:
        raise ParseError(ParseErrorKind.NumberOutOfRange)
    return s[end:], n


def _parse_derivation_step_number(s: str) -> Tuple[str, int]:
    rest, n = _parse_number_up_to(s, HARDENED_INDEX - 1)
    if rest.startswith("'"):
        return rest[1:], n + HARDENED_INDEX
    return rest, n


def _parse_derivation_suffix(s: str) -> Tuple[str, Tuple[int, int]]:
    if not s.startswith("/"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    s = s[1:]
    if s.startswith("**"):
        return s[2:], (0, 1)
    if s.startswith("<"):
        s = s[1:]
        s, n1 = _parse_derivation_step_number(s)
        if not s.startswith(";"):
            raise ParseError(ParseErrorKind.InvalidSyntax)
        s, n2 = _parse_derivation_step_number(s[1:])
        if not s.startswith(">/*"):
            raise ParseError(ParseErrorKind.InvalidSyntax)
        return s[3:], (n1, n2)
    raise ParseError(ParseErrorKind.InvalidSyntax)


def _parse_key_expression(s: str, ctx: ParseContext) -> Tuple[str, KeyExpression]:
    if s.startswith("musig("):
        if not ctx.musig_allowed():
            raise ParseError(ParseErrorKind.InvalidScriptContext)
        return _parse_musig_key_expression(s)
    if not s.startswith("@"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    rest, idx = _parse_number_up_to(s[1:], 0xFFFFFFFF)
    rest, (n1, n2) = _parse_derivation_suffix(rest)
    return rest, KeyExpression.plain(idx, n1, n2)


def _parse_musig_key_expression(s: str) -> Tuple[str, KeyExpression]:
    rest = s[6:]
    indices: List[int] = []
    while True:
        if not rest.startswith("@"):
            raise ParseError(ParseErrorKind.InvalidSyntax)
        rest, idx = _parse_number_up_to(rest[1:], 0xFFFFFFFF)
        if idx in indices:
            raise ParseError(ParseErrorKind.InvalidKey)
        indices.append(idx)
        if rest.startswith(","):
            rest = rest[1:]
        else:
            break
    if len(indices) < 2:
        raise ParseError(ParseErrorKind.TooFewKeyExpressions)
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    rest = rest[1:]
    rest, (n1, n2) = _parse_derivation_suffix(rest)
    return rest, KeyExpression.musig(indices, n1, n2)


# ---------------------------------------------------------------------------
# DescriptorTemplate (tagged-union AST) + TapTree
# ---------------------------------------------------------------------------

# Wrapper variant tags, kept aligned with the Rust enum names.
_WRAPPER_TAGS = {
    "a": "A",
    "s": "S",
    "c": "C",
    "t": "T",
    "d": "D",
    "v": "V",
    "j": "J",
    "n": "N",
    "l": "L",
    "u": "U",
}
_WRAPPER_KINDS = set(_WRAPPER_TAGS.values())


@dataclass
class TapTree:
    """Tagged-union taptree node: ``kind`` is ``"Script"`` or ``"Branch"``."""

    kind: str
    args: Tuple

    @classmethod
    def script(cls, desc: "DescriptorTemplate") -> "TapTree":
        return cls(kind="Script", args=(desc,))

    @classmethod
    def branch(cls, left: "TapTree", right: "TapTree") -> "TapTree":
        return cls(kind="Branch", args=(left, right))

    def tapleaves(self) -> Iterator["DescriptorTemplate"]:
        stack: List[TapTree] = [self]
        while stack:
            node = stack.pop()
            if node.kind == "Script":
                yield node.args[0]
            else:
                stack.append(node.args[1])
                stack.append(node.args[0])

    def __str__(self) -> str:
        if self.kind == "Script":
            return str(self.args[0])
        return "{" + str(self.args[0]) + "," + str(self.args[1]) + "}"


@dataclass
class DescriptorTemplate:
    """BIP-388 descriptor template node.

    ``kind`` names the Rust variant (e.g. ``"Pkh"``, ``"Sh"``, ``"Tr"``,
    ``"A"``..``"U"``); ``args`` carries the variant payload as a tuple
    laid out to match the Rust enum.
    """

    kind: str
    args: Tuple = ()

    # --- construction helpers ------------------------------------------------

    @classmethod
    def from_str(cls, s: str) -> "DescriptorTemplate":
        rest, desc = _parse_descriptor(s, ParseContext.TopLevel, 0)
        if rest:
            raise ParseError(ParseErrorKind.TrailingInput)
        return desc

    # --- introspection -------------------------------------------------------

    def is_wrapper(self) -> bool:
        return self.kind in _WRAPPER_KINDS

    def placeholders(
        self,
    ) -> Iterator[Tuple[KeyExpression, Optional["DescriptorTemplate"]]]:
        """Yield `(key_expression, optional_tapleaf_descriptor)` pairs.

        Tapleaf context is `None` outside `tr(...)`; inside, each leaf
        carries its top-level descriptor as the second element of the
        pair, matching the Rust `DescriptorTemplateIter`.
        """
        # Stack entries: (descriptor, tapleaf_desc)
        fragments: List[Tuple[DescriptorTemplate, Optional[DescriptorTemplate]]] = [
            (self, None)
        ]
        placeholders: List[Tuple[KeyExpression, Optional[DescriptorTemplate]]] = []
        while placeholders or fragments:
            if placeholders:
                yield placeholders.pop()
                continue
            frag, tapleaf_desc = fragments.pop()
            k = frag.kind
            if k in ("Sh", "Wsh") or k in _WRAPPER_KINDS:
                fragments.append((frag.args[0], tapleaf_desc))
            elif k == "Andor":
                fragments.append((frag.args[2], tapleaf_desc))
                fragments.append((frag.args[1], tapleaf_desc))
                fragments.append((frag.args[0], tapleaf_desc))
            elif k in (
                "Or_b",
                "Or_c",
                "Or_d",
                "Or_i",
                "And_v",
                "And_b",
                "And_n",
            ):
                fragments.append((frag.args[1], tapleaf_desc))
                fragments.append((frag.args[0], tapleaf_desc))
            elif k == "Tr":
                key, tree = frag.args
                placeholders.append((key, None))
                if tree is not None:
                    leaves = list(tree.tapleaves())
                    leaves.reverse()
                    for leaf in leaves:
                        fragments.append((leaf, leaf))
            elif k in ("Pkh", "Wpkh", "Pk", "Pk_k", "Pk_h"):
                yield (frag.args[0], tapleaf_desc)
            elif k in ("Sortedmulti", "Sortedmulti_a", "Multi", "Multi_a"):
                _threshold, keys = frag.args
                for kp in reversed(keys):
                    placeholders.append((kp, tapleaf_desc))
            elif k == "Thresh":
                _k, descs = frag.args
                for d in reversed(descs):
                    fragments.append((d, tapleaf_desc))
            elif k in (
                "Zero",
                "One",
                "Older",
                "After",
                "Sha256",
                "Ripemd160",
                "Hash256",
                "Hash160",
            ):
                pass
            else:
                raise AssertionError(f"unknown descriptor kind {k!r}")

    # --- display -------------------------------------------------------------

    def __str__(self) -> str:
        return _format_descriptor(self)


# Argument layout (used by the cleartext matcher to drive pattern matching).
# Each entry is a tuple of kind strings: 'Key' | 'Num' | 'KeyList' | 'Sub' | 'Tree'.
VARIANT_ARG_KINDS: dict = {
    "Sh": ("Sub",),
    "Wsh": ("Sub",),
    "Pkh": ("Key",),
    "Wpkh": ("Key",),
    "Pk": ("Key",),
    "Pk_k": ("Key",),
    "Pk_h": ("Key",),
    "Older": ("Num",),
    "After": ("Num",),
    "Multi": ("Num", "KeyList"),
    "Multi_a": ("Num", "KeyList"),
    "Sortedmulti": ("Num", "KeyList"),
    "Sortedmulti_a": ("Num", "KeyList"),
    "Tr": ("Key", "Tree"),
    "Andor": ("Sub", "Sub", "Sub"),
    "And_v": ("Sub", "Sub"),
    "And_b": ("Sub", "Sub"),
    "And_n": ("Sub", "Sub"),
    "Or_b": ("Sub", "Sub"),
    "Or_c": ("Sub", "Sub"),
    "Or_d": ("Sub", "Sub"),
    "Or_i": ("Sub", "Sub"),
    "Thresh": ("Num", "Sub"),  # second arg is Vec<Sub> — handled specially
    "Zero": (),
    "One": (),
    "Sha256": (),
    "Ripemd160": (),
    "Hash256": (),
    "Hash160": (),
    "A": ("Sub",),
    "S": ("Sub",),
    "C": ("Sub",),
    "T": ("Sub",),
    "D": ("Sub",),
    "V": ("Sub",),
    "J": ("Sub",),
    "N": ("Sub",),
    "L": ("Sub",),
    "U": ("Sub",),
}


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------


def _format_descriptor(d: DescriptorTemplate) -> str:
    k = d.kind
    a = d.args
    if k == "Sh":
        return f"sh({a[0]})"
    if k == "Wsh":
        return f"wsh({a[0]})"
    if k == "Pkh":
        return f"pkh({a[0]})"
    if k == "Wpkh":
        return f"wpkh({a[0]})"
    if k == "Pk":
        return f"pk({a[0]})"
    if k == "Pk_k":
        return f"pk_k({a[0]})"
    if k == "Pk_h":
        return f"pk_h({a[0]})"
    if k == "Older":
        return f"older({a[0]})"
    if k == "After":
        return f"after({a[0]})"
    if k == "Multi":
        return "multi(" + str(a[0]) + "".join("," + str(kp) for kp in a[1]) + ")"
    if k == "Multi_a":
        return "multi_a(" + str(a[0]) + "".join("," + str(kp) for kp in a[1]) + ")"
    if k == "Sortedmulti":
        return (
            "sortedmulti(" + str(a[0]) + "".join("," + str(kp) for kp in a[1]) + ")"
        )
    if k == "Sortedmulti_a":
        return (
            "sortedmulti_a(" + str(a[0]) + "".join("," + str(kp) for kp in a[1]) + ")"
        )
    if k == "Tr":
        key, tree = a
        if tree is None:
            return f"tr({key})"
        return f"tr({key},{tree})"
    if k == "Zero":
        return "0"
    if k == "One":
        return "1"
    if k in ("Sha256", "Hash256"):
        return f"{k.lower()}({a[0].hex()})"
    if k in ("Ripemd160", "Hash160"):
        return f"{k.lower()}({a[0].hex()})"
    if k == "Andor":
        return f"andor({a[0]},{a[1]},{a[2]})"
    if k in ("And_v", "And_b", "And_n", "Or_b", "Or_c", "Or_d", "Or_i"):
        return f"{k.lower()}({a[0]},{a[1]})"
    if k == "Thresh":
        return "thresh(" + str(a[0]) + "".join("," + str(d2) for d2 in a[1]) + ")"
    if k in _WRAPPER_KINDS:
        inner = a[0]
        sep = "" if inner.is_wrapper() else ":"
        return f"{k.lower()}{sep}{inner}"
    raise AssertionError(f"unknown descriptor kind {k!r}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _parse_descriptor(
    s: str, ctx: ParseContext, depth: int
) -> Tuple[str, DescriptorTemplate]:
    if depth >= MAX_PARSE_DEPTH:
        raise ParseError(ParseErrorKind.NestingTooDeep)
    depth += 1

    # Strip optional wrapper prefix "abc:".
    alpha_end = 0
    while alpha_end < len(s) and s[alpha_end].isalpha():
        alpha_end += 1
    if alpha_end > 0 and alpha_end < len(s) and s[alpha_end] == ":":
        wrappers = s[:alpha_end]
        s = s[alpha_end + 1 :]
    else:
        wrappers = ""

    s, inner = _parse_inner_descriptor(s, ctx, depth)

    for ch in reversed(wrappers):
        variant = _WRAPPER_TAGS.get(ch)
        if variant is None:
            raise ParseError(ParseErrorKind.InvalidSyntax)
        inner = DescriptorTemplate(kind=variant, args=(inner,))
    return s, inner


def _parse_inner_descriptor(
    s: str, ctx: ParseContext, depth: int
) -> Tuple[str, DescriptorTemplate]:
    # Longer names first.
    if s.startswith("sortedmulti_a("):
        return _parse_threshold_kp_fragment(s, "sortedmulti_a", "Sortedmulti_a", ctx, MAX_KEYS_MULTI_A)
    if s.startswith("sortedmulti("):
        return _parse_threshold_kp_fragment(s, "sortedmulti", "Sortedmulti", ctx, MAX_KEYS_MULTI)
    if s.startswith("multi_a("):
        return _parse_threshold_kp_fragment(s, "multi_a", "Multi_a", ctx, MAX_KEYS_MULTI_A)
    if s.startswith("multi("):
        return _parse_threshold_kp_fragment(s, "multi", "Multi", ctx, MAX_KEYS_MULTI)
    if s.startswith("thresh("):
        return _parse_thresh(s, ctx, depth)
    if s.startswith("wsh("):
        if not ctx.wsh_allowed():
            raise ParseError(ParseErrorKind.InvalidScriptContext)
        inner_ctx = (
            ParseContext.Segwit
            if ctx is ParseContext.TopLevel
            else ParseContext.WrappedSegwit
        )
        rest, scripts = _parse_n_subscripts(s[4:], inner_ctx, depth, 1)
        return rest, DescriptorTemplate(kind="Wsh", args=(scripts[0],))
    if s.startswith("sh("):
        if not ctx.sh_allowed():
            raise ParseError(ParseErrorKind.InvalidScriptContext)
        rest, scripts = _parse_n_subscripts(s[3:], ParseContext.Legacy, depth, 1)
        return rest, DescriptorTemplate(kind="Sh", args=(scripts[0],))
    if s.startswith("wpkh("):
        if not ctx.wpkh_allowed():
            raise ParseError(ParseErrorKind.InvalidScriptContext)
        return _parse_kp_fragment(s, "wpkh", "Wpkh", ctx)
    if s.startswith("pkh("):
        return _parse_kp_fragment(s, "pkh", "Pkh", ctx)
    if s.startswith("tr("):
        if not ctx.tr_allowed():
            raise ParseError(ParseErrorKind.InvalidScriptContext)
        return _parse_tr(s, depth)
    if s.startswith("pk_k("):
        return _parse_kp_fragment(s, "pk_k", "Pk_k", ctx)
    if s.startswith("pk_h("):
        return _parse_kp_fragment(s, "pk_h", "Pk_h", ctx)
    if s.startswith("pk("):
        return _parse_kp_fragment(s, "pk", "Pk", ctx)
    if s.startswith("older("):
        return _parse_num_fragment(s, "older", MAX_OLDER_AFTER, "Older")
    if s.startswith("after("):
        return _parse_num_fragment(s, "after", MAX_OLDER_AFTER, "After")
    if s.startswith("sha256("):
        return _parse_hex_fragment(s, "sha256", 32, "Sha256")
    if s.startswith("hash256("):
        return _parse_hex_fragment(s, "hash256", 32, "Hash256")
    if s.startswith("ripemd160("):
        return _parse_hex_fragment(s, "ripemd160", 20, "Ripemd160")
    if s.startswith("hash160("):
        return _parse_hex_fragment(s, "hash160", 20, "Hash160")
    if s.startswith("andor("):
        rest, scripts = _parse_n_subscripts(s[6:], ctx, depth, 3)
        return rest, DescriptorTemplate(kind="Andor", args=tuple(scripts))
    if s.startswith("and_b("):
        rest, scripts = _parse_n_subscripts(s[6:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="And_b", args=tuple(scripts))
    if s.startswith("and_v("):
        rest, scripts = _parse_n_subscripts(s[6:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="And_v", args=tuple(scripts))
    if s.startswith("and_n("):
        rest, scripts = _parse_n_subscripts(s[6:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="And_n", args=tuple(scripts))
    if s.startswith("or_b("):
        rest, scripts = _parse_n_subscripts(s[5:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="Or_b", args=tuple(scripts))
    if s.startswith("or_c("):
        rest, scripts = _parse_n_subscripts(s[5:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="Or_c", args=tuple(scripts))
    if s.startswith("or_d("):
        rest, scripts = _parse_n_subscripts(s[5:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="Or_d", args=tuple(scripts))
    if s.startswith("or_i("):
        rest, scripts = _parse_n_subscripts(s[5:], ctx, depth, 2)
        return rest, DescriptorTemplate(kind="Or_i", args=tuple(scripts))
    if s.startswith("0"):
        return s[1:], DescriptorTemplate(kind="Zero", args=())
    if s.startswith("1"):
        return s[1:], DescriptorTemplate(kind="One", args=())
    raise ParseError(ParseErrorKind.UnrecognizedFragment)


def _parse_kp_fragment(
    s: str, name: str, variant: str, ctx: ParseContext
) -> Tuple[str, DescriptorTemplate]:
    rest = s[len(name) + 1 :]
    rest, kp = _parse_key_expression(rest, ctx)
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind=variant, args=(kp,))


def _parse_num_fragment(
    s: str, name: str, max_value: int, variant: str
) -> Tuple[str, DescriptorTemplate]:
    rest = s[len(name) + 1 :]
    rest, n = _parse_number_up_to(rest, max_value)
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind=variant, args=(n,))


def _parse_hex_fragment(
    s: str, name: str, n_bytes: int, variant: str
) -> Tuple[str, DescriptorTemplate]:
    rest = s[len(name) + 1 :]
    hex_len = n_bytes * 2
    if len(rest) < hex_len:
        raise ParseError(ParseErrorKind.InvalidLength)
    try:
        b = bytes.fromhex(rest[:hex_len])
    except ValueError:
        raise ParseError(ParseErrorKind.InvalidHex)
    rest = rest[hex_len:]
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind=variant, args=(b,))


def _parse_threshold_kp_fragment(
    s: str, name: str, variant: str, ctx: ParseContext, max_keys: int
) -> Tuple[str, DescriptorTemplate]:
    rest = s[len(name) + 1 :]
    rest, threshold = _parse_number_up_to(rest, 0xFFFFFFFF)
    keys: List[KeyExpression] = []
    while rest.startswith(","):
        if len(keys) >= max_keys:
            raise ParseError(ParseErrorKind.TooManyKeys)
        try:
            new_rest, kp = _parse_key_expression(rest[1:], ctx)
        except ParseError as e:
            if e.kind is ParseErrorKind.InvalidScriptContext:
                raise
            break
        keys.append(kp)
        rest = new_rest
    if len(keys) < 2:
        raise ParseError(ParseErrorKind.TooFewKeyExpressions)
    if threshold == 0 or threshold > len(keys):
        raise ParseError(ParseErrorKind.InvalidMultisigQuorum)
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind=variant, args=(threshold, keys))


def _parse_n_subscripts(
    s: str, ctx: ParseContext, depth: int, n: int
) -> Tuple[str, List[DescriptorTemplate]]:
    rest = s
    scripts: List[DescriptorTemplate] = []
    for i in range(n):
        rest, desc = _parse_descriptor(rest, ctx, depth)
        scripts.append(desc)
        if i + 1 < n:
            if not rest.startswith(","):
                raise ParseError(ParseErrorKind.InvalidSyntax)
            rest = rest[1:]
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], scripts


def _parse_thresh(s: str, ctx: ParseContext, depth: int) -> Tuple[str, DescriptorTemplate]:
    rest, k = _parse_number_up_to(s[7:], 0xFFFFFFFF)
    if not rest.startswith(","):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    rest, first = _parse_descriptor(rest[1:], ctx, depth)
    scripts: List[DescriptorTemplate] = [first]
    while rest.startswith(","):
        try:
            new_rest, d = _parse_descriptor(rest[1:], ctx, depth)
        except ParseError as e:
            if e.kind is ParseErrorKind.NestingTooDeep:
                raise
            break
        scripts.append(d)
        rest = new_rest
    if k == 0:
        raise ParseError(ParseErrorKind.InvalidMultisigQuorum)
    if k > len(scripts):
        raise ParseError(ParseErrorKind.ThreshExceedsScripts)
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind="Thresh", args=(k, scripts))


def _parse_tr(s: str, depth: int) -> Tuple[str, DescriptorTemplate]:
    rest, key = _parse_key_expression(s[3:], ParseContext.Taproot)
    if rest.startswith(","):
        rest, tree = _parse_tap_tree(rest[1:], depth)
    else:
        tree = None
    if not rest.startswith(")"):
        raise ParseError(ParseErrorKind.InvalidSyntax)
    return rest[1:], DescriptorTemplate(kind="Tr", args=(key, tree))


def _parse_tap_tree(s: str, depth: int) -> Tuple[str, TapTree]:
    if depth >= MAX_PARSE_DEPTH:
        raise ParseError(ParseErrorKind.NestingTooDeep)
    depth += 1
    if s.startswith("{"):
        rest, left = _parse_tap_tree(s[1:], depth)
        if not rest.startswith(","):
            raise ParseError(ParseErrorKind.InvalidSyntax)
        rest, right = _parse_tap_tree(rest[1:], depth)
        if not rest.startswith("}"):
            raise ParseError(ParseErrorKind.InvalidSyntax)
        return rest[1:], TapTree.branch(left, right)
    rest, desc = _parse_descriptor(s, ParseContext.Taproot, depth)
    return rest, TapTree.script(desc)


# ---------------------------------------------------------------------------
# Render with concrete keys (to_descriptor)
# ---------------------------------------------------------------------------


def _write_key_expression(
    kp: KeyExpression,
    key_information: Sequence[KeyInformation],
    is_change: bool,
    address_index: int,
) -> str:
    step = kp.num2 if is_change else kp.num1
    if kp.is_plain():
        idx = kp.key_type[1]
        if idx >= len(key_information):
            raise ParseError(ParseErrorKind.InvalidKeyIndex)
        return f"{key_information[idx]}/{step}/{address_index}"
    parts = ["musig("]
    indices = kp.key_type[1]
    for i, idx in enumerate(indices):
        if i > 0:
            parts.append(",")
        if idx >= len(key_information):
            raise ParseError(ParseErrorKind.InvalidKeyIndex)
        parts.append(str(key_information[idx]))
    parts.append(f")/{step}/{address_index}")
    return "".join(parts)


def _write_key_expressions(
    kps: Sequence[KeyExpression],
    key_information: Sequence[KeyInformation],
    is_change: bool,
    address_index: int,
) -> str:
    return ",".join(
        _write_key_expression(kp, key_information, is_change, address_index)
        for kp in kps
    )


def _to_descriptor_tap_tree(
    tree: TapTree,
    key_information: Sequence[KeyInformation],
    is_change: bool,
    address_index: int,
) -> str:
    if tree.kind == "Script":
        return _to_descriptor_inner(tree.args[0], key_information, is_change, address_index)
    left = _to_descriptor_tap_tree(tree.args[0], key_information, is_change, address_index)
    right = _to_descriptor_tap_tree(tree.args[1], key_information, is_change, address_index)
    return "{" + left + "," + right + "}"


def _to_descriptor_inner(
    d: DescriptorTemplate,
    key_information: Sequence[KeyInformation],
    is_change: bool,
    address_index: int,
) -> str:
    k = d.kind
    a = d.args
    if k == "Sh":
        return f"sh({_to_descriptor_inner(a[0], key_information, is_change, address_index)})"
    if k == "Wsh":
        return f"wsh({_to_descriptor_inner(a[0], key_information, is_change, address_index)})"
    if k == "Pkh":
        return f"pkh({_write_key_expression(a[0], key_information, is_change, address_index)})"
    if k == "Wpkh":
        return f"wpkh({_write_key_expression(a[0], key_information, is_change, address_index)})"
    if k == "Pk":
        return f"pk({_write_key_expression(a[0], key_information, is_change, address_index)})"
    if k == "Pk_k":
        return f"pk_k({_write_key_expression(a[0], key_information, is_change, address_index)})"
    if k == "Pk_h":
        return f"pk_h({_write_key_expression(a[0], key_information, is_change, address_index)})"
    if k == "Sortedmulti":
        return (
            f"sortedmulti({a[0]},"
            + _write_key_expressions(a[1], key_information, is_change, address_index)
            + ")"
        )
    if k == "Sortedmulti_a":
        return (
            f"sortedmulti_a({a[0]},"
            + _write_key_expressions(a[1], key_information, is_change, address_index)
            + ")"
        )
    if k == "Multi":
        return (
            f"multi({a[0]},"
            + _write_key_expressions(a[1], key_information, is_change, address_index)
            + ")"
        )
    if k == "Multi_a":
        return (
            f"multi_a({a[0]},"
            + _write_key_expressions(a[1], key_information, is_change, address_index)
            + ")"
        )
    if k == "Tr":
        key, tree = a
        head = f"tr({_write_key_expression(key, key_information, is_change, address_index)}"
        if tree is None:
            return head + ")"
        return (
            head
            + ","
            + _to_descriptor_tap_tree(tree, key_information, is_change, address_index)
            + ")"
        )
    if k == "Zero":
        return "0"
    if k == "One":
        return "1"
    if k == "Older":
        return f"older({a[0]})"
    if k == "After":
        return f"after({a[0]})"
    if k in ("Sha256", "Hash256", "Ripemd160", "Hash160"):
        return f"{k.lower()}({a[0].hex()})"
    if k == "Andor":
        return (
            "andor("
            + _to_descriptor_inner(a[0], key_information, is_change, address_index)
            + ","
            + _to_descriptor_inner(a[1], key_information, is_change, address_index)
            + ","
            + _to_descriptor_inner(a[2], key_information, is_change, address_index)
            + ")"
        )
    if k in ("And_v", "And_b", "And_n", "Or_b", "Or_c", "Or_d", "Or_i"):
        return (
            f"{k.lower()}("
            + _to_descriptor_inner(a[0], key_information, is_change, address_index)
            + ","
            + _to_descriptor_inner(a[1], key_information, is_change, address_index)
            + ")"
        )
    if k == "Thresh":
        parts = [f"thresh({a[0]}"]
        for sub in a[1]:
            parts.append(",")
            parts.append(
                _to_descriptor_inner(sub, key_information, is_change, address_index)
            )
        parts.append(")")
        return "".join(parts)
    if k in _WRAPPER_KINDS:
        inner = a[0]
        sep = "" if inner.is_wrapper() else ":"
        return (
            f"{k.lower()}{sep}"
            + _to_descriptor_inner(inner, key_information, is_change, address_index)
        )
    raise AssertionError(f"unknown descriptor kind {k!r}")


def to_descriptor(
    d: Union[DescriptorTemplate, TapTree],
    key_information: Sequence[KeyInformation],
    is_change: bool,
    address_index: int,
) -> str:
    """Render a descriptor template (or tap-tree) with concrete keys."""
    if isinstance(d, TapTree):
        return _to_descriptor_tap_tree(d, key_information, is_change, address_index)
    return _to_descriptor_inner(d, key_information, is_change, address_index)
