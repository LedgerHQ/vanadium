"""BIP-388 cleartext display (forward direction).

Loads the same `cleartext.toml` spec consumed by the Rust crate's
`build.rs`, and implements the runtime classifier, the confusion-score
helper, and the `to_cleartext` renderer. The reverse direction
(parsing a cleartext description back into descriptors) is part of the
`cleartext-decode` feature and is intentionally not ported.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .descriptor import VARIANT_ARG_KINDS, DescriptorTemplate, KeyExpression
from .time_fmt import format_seconds, format_utc_date

# `older(n)` with this bit set encodes a time-based relative locktime
# (BIP-68); the rest of the value is in 512-second units.
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22

MAX_CONFUSION_SCORE = 3600

_U64_MAX = (1 << 64) - 1


def _sat_mul(a: int, b: int) -> int:
    r = a * b
    return r if r <= _U64_MAX else _U64_MAX


# ---------------------------------------------------------------------------
# Spec model
# ---------------------------------------------------------------------------

# Binding kind → (rust_type_label, cleartext_variant, range)
# Ranges are inclusive-lo, exclusive-hi; None on hi means open-ended.
_BINDING_KINDS: Dict[str, Tuple[Optional[int], Optional[int]]] = {
    "Key": (None, None),
    "KeyList": (None, None),
    "Threshold": (None, None),
    "Blocks": (1, 65_536),
    "RelativeTime": (4_194_305, 4_259_840),
    "BlockHeight": (1, 500_000_000),
    "Timestamp": (500_000_000, None),
    "Leaves": (None, None),
}


def _binding_kind_for_name(name: str) -> str:
    base = name.rstrip("0123456789")
    return {
        "key": "Key",
        "internal_key": "Key",
        "keys": "KeyList",
        "threshold": "Threshold",
        "blocks": "Blocks",
        "relative_time": "RelativeTime",
        "block_height": "BlockHeight",
        "timestamp": "Timestamp",
        "leaves": "Leaves",
    }[base]


@dataclass
class PatBinding:
    name: str
    kind: str  # one of _BINDING_KINDS


@dataclass
class PatMusig:
    threshold: str  # binding name
    keys: str  # binding name


@dataclass
class PatSub:
    wrappers: List[str]  # variant names like 'V', 'A', ...
    inner: "Pattern"


PatternArg = Any  # PatBinding | PatMusig | PatSub


@dataclass
class Pattern:
    keyword: str
    args: List[PatternArg]


_KEYWORD_TO_VARIANT = {
    "sh": "Sh",
    "wsh": "Wsh",
    "pkh": "Pkh",
    "wpkh": "Wpkh",
    "sortedmulti": "Sortedmulti",
    "sortedmulti_a": "Sortedmulti_a",
    "tr": "Tr",
    "pk": "Pk",
    "pk_k": "Pk_k",
    "pk_h": "Pk_h",
    "older": "Older",
    "after": "After",
    "andor": "Andor",
    "and_v": "And_v",
    "and_b": "And_b",
    "and_n": "And_n",
    "or_b": "Or_b",
    "or_c": "Or_c",
    "or_d": "Or_d",
    "or_i": "Or_i",
    "thresh": "Thresh",
    "multi": "Multi",
    "multi_a": "Multi_a",
}

_WRAPPER_VARIANT = {
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


# ---------------------------------------------------------------------------
# Pattern parser (matches the Rust build.rs grammar)
# ---------------------------------------------------------------------------


class _PatternParser:
    def __init__(self, src: str):
        self.src = src
        self.pos = 0

    def _skip_ws(self) -> None:
        while self.pos < len(self.src) and self.src[self.pos].isspace():
            self.pos += 1

    def _peek(self) -> Optional[str]:
        if self.pos < len(self.src):
            return self.src[self.pos]
        return None

    def _bump(self, ch: str) -> None:
        self._skip_ws()
        if self._peek() != ch:
            raise ValueError(
                f"expected {ch!r} at byte {self.pos} in {self.src!r}"
            )
        self.pos += 1

    def _try_bump(self, ch: str) -> bool:
        self._skip_ws()
        if self._peek() == ch:
            self.pos += 1
            return True
        return False

    def _parse_ident(self) -> str:
        self._skip_ws()
        start = self.pos
        while self.pos < len(self.src) and (
            self.src[self.pos].isalnum() or self.src[self.pos] == "_"
        ):
            self.pos += 1
        if self.pos == start:
            raise ValueError(
                f"expected identifier at byte {self.pos} in {self.src!r}"
            )
        return self.src[start : self.pos]

    def parse_pattern(self) -> Pattern:
        kw = self._parse_ident()
        if kw not in _KEYWORD_TO_VARIANT:
            raise ValueError(f"unknown descriptor keyword {kw!r}")
        if not self._try_bump("("):
            return Pattern(keyword=kw, args=[])
        arg_kinds = VARIANT_ARG_KINDS[_KEYWORD_TO_VARIANT[kw]]
        args: List[PatternArg] = []
        if not self._try_bump(")"):
            while True:
                ak = arg_kinds[len(args)] if len(args) < len(arg_kinds) else "Sub"
                args.append(self._parse_arg(ak))
                self._skip_ws()
                if self._try_bump(")"):
                    break
                self._bump(",")
        return Pattern(keyword=kw, args=args)

    def _parse_binding_name(self) -> str:
        self._bump("$")
        return self._parse_ident()

    def _parse_arg(self, expected: str) -> PatternArg:
        self._skip_ws()
        if self._peek() == "$":
            name = self._parse_binding_name()
            kind = _binding_kind_for_name(name)
            _check_kind_matches(name, kind, expected)
            return PatBinding(name=name, kind=kind)
        saved = self.pos
        try:
            ident = self._parse_ident()
        except ValueError:
            ident = ""
        if ident == "musig":
            if expected != "Key":
                raise ValueError(
                    f"musig(...) is only allowed in a Key position; got {expected}"
                )
            self._bump("(")
            threshold = self._parse_binding_name()
            if _binding_kind_for_name(threshold) != "Threshold":
                raise ValueError(
                    f"first arg of musig(...) must be a $threshold binding, got ${threshold}"
                )
            self._bump(",")
            keys = self._parse_binding_name()
            if _binding_kind_for_name(keys) != "KeyList":
                raise ValueError(
                    f"second arg of musig(...) must be a $keys binding, got ${keys}"
                )
            self._bump(")")
            return PatMusig(threshold=threshold, keys=keys)
        # Rewind: not a musig — it's the keyword for a (possibly wrapped) sub-pattern.
        self.pos = saved
        wrappers: List[str] = []
        while True:
            snap = self.pos
            try:
                name = self._parse_ident()
            except ValueError:
                name = ""
            self._skip_ws()
            if name and self._peek() == ":":
                for c in name:
                    v = _WRAPPER_VARIANT.get(c)
                    if v is None:
                        raise ValueError(f"unknown wrapper character {c!r}")
                    wrappers.append(v)
                self.pos += 1  # consume ':'
                continue
            self.pos = snap
            break
        if expected != "Sub" and wrappers:
            raise ValueError(
                f"wrappers are only allowed in Sub positions; got {expected}"
            )
        inner = self.parse_pattern()
        return PatSub(wrappers=wrappers, inner=inner)


def _check_kind_matches(name: str, kind: str, expected: str) -> None:
    ok = (
        (kind == "Key" and expected == "Key")
        or (kind == "KeyList" and expected == "KeyList")
        or (
            kind in ("Threshold", "Blocks", "RelativeTime", "BlockHeight", "Timestamp")
            and expected == "Num"
        )
        or (kind == "Leaves" and expected == "Tree")
    )
    if not ok:
        raise ValueError(
            f"binding ${name!r} (kind {kind}) doesn't match the AST position kind {expected}"
        )


# ---------------------------------------------------------------------------
# Processed entry (one TOML [[top_level]] or [[tapleaf]])
# ---------------------------------------------------------------------------


@dataclass
class CleartextToken:
    is_literal: bool
    text: str = ""  # only for literal
    name: str = ""  # only for field
    kind: str = ""  # only for field


@dataclass
class Entry:
    name: str
    patterns: List[Pattern]
    field_order: List[str]
    field_kinds: Dict[str, str]
    cleartext_tokens: List[CleartextToken]
    recurses: bool  # whether the entry has a $leaves field
    plain_pattern_count: int
    musig_pattern_count: int


def _pattern_uses_musig(p: Pattern) -> bool:
    for arg in p.args:
        if isinstance(arg, PatMusig):
            return True
        if isinstance(arg, PatSub) and _pattern_uses_musig(arg.inner):
            return True
    return False


def _pattern_bindings(p: Pattern) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []

    def walk(pp: Pattern) -> None:
        for arg in pp.args:
            if isinstance(arg, PatBinding):
                out.append((arg.name, arg.kind))
            elif isinstance(arg, PatMusig):
                out.append((arg.threshold, "Threshold"))
                out.append((arg.keys, "KeyList"))
            elif isinstance(arg, PatSub):
                walk(arg.inner)

    walk(p)
    return out


def _process_entries(raw: List[dict]) -> List[Entry]:
    out: List[Entry] = []
    for entry_raw in raw:
        name = entry_raw["name"]
        patterns_src = entry_raw["patterns"]
        cleartext_src = entry_raw["cleartext"]
        patterns: List[Pattern] = []
        for src in patterns_src:
            p = _PatternParser(src)
            pat = p.parse_pattern()
            p._skip_ws()
            if p.pos != len(p.src):
                raise ValueError(
                    f"entry '{name}': pattern {src!r}: trailing input at byte {p.pos}"
                )
            patterns.append(pat)
        # Union of bindings across patterns, preserving first-seen order.
        order: List[str] = []
        kinds: Dict[str, str] = {}
        for pat in patterns:
            for bname, bkind in _pattern_bindings(pat):
                if bname in kinds:
                    if kinds[bname] != bkind:
                        raise ValueError(
                            f"entry '{name}': binding ${bname} has inconsistent "
                            f"kinds across patterns: {kinds[bname]} vs {bkind}"
                        )
                else:
                    order.append(bname)
                    kinds[bname] = bkind
        # Parse the cleartext template.
        tokens: List[CleartextToken] = []
        for item in cleartext_src:
            if item.startswith("$"):
                fname = item[1:]
                if fname not in kinds:
                    raise ValueError(
                        f"entry '{name}': cleartext references unknown field ${fname}"
                    )
                if kinds[fname] == "Leaves":
                    raise ValueError(
                        f"entry '{name}': cleartext cannot reference $leaves"
                    )
                tokens.append(
                    CleartextToken(is_literal=False, name=fname, kind=kinds[fname])
                )
            else:
                tokens.append(CleartextToken(is_literal=True, text=item))
        recurses = any(k == "Leaves" for k in kinds.values())
        plain_count = sum(1 for p in patterns if not _pattern_uses_musig(p))
        musig_count = sum(1 for p in patterns if _pattern_uses_musig(p))
        out.append(
            Entry(
                name=name,
                patterns=patterns,
                field_order=order,
                field_kinds=kinds,
                cleartext_tokens=tokens,
                recurses=recurses,
                plain_pattern_count=plain_count,
                musig_pattern_count=musig_count,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------


def _default_spec_path() -> Path:
    return (
        Path(__file__).resolve().parent.parent.parent
        / "src"
        / "cleartext"
        / "specs"
        / "cleartext.toml"
    )


def _load_spec() -> Tuple[List[Entry], List[Entry]]:
    path = _default_spec_path()
    with open(path, "rb") as f:
        data = tomllib.load(f)
    top_level = _process_entries(data.get("top_level", []))
    tapleaf = _process_entries(data.get("tapleaf", []))
    return top_level, tapleaf


TOP_LEVEL_SPECS, TAPLEAF_SPECS = _load_spec()
_TOP_LEVEL_BY_NAME = {e.name: e for e in TOP_LEVEL_SPECS}
_TAPLEAF_BY_NAME = {e.name: e for e in TAPLEAF_SPECS}
_TAPLEAF_ORDER = {e.name: i for i, e in enumerate(TAPLEAF_SPECS)}


# ---------------------------------------------------------------------------
# Classification (runtime pattern matcher)
# ---------------------------------------------------------------------------


@dataclass
class _ClassInstance:
    """A classified descriptor or tapleaf.

    `name` is ``"Other"`` for the catch-all, in which case ``other_str``
    carries the raw descriptor string (tapleaves only).
    """

    name: str
    fields: Dict[str, Any] = field(default_factory=dict)
    other_str: Optional[str] = None


def _match_arg(
    parg: PatternArg,
    target_arg: Any,
    arg_kind: str,
    bindings: Dict[str, Any],
) -> bool:
    if isinstance(parg, PatBinding):
        if arg_kind == "Key":
            if not isinstance(target_arg, KeyExpression) or not target_arg.is_plain():
                return False
            bindings[parg.name] = target_arg
            return True
        if arg_kind == "Num":
            if not isinstance(target_arg, int):
                return False
            lo, hi = _BINDING_KINDS[parg.kind]
            if lo is not None and target_arg < lo:
                return False
            if hi is not None and target_arg >= hi:
                return False
            bindings[parg.name] = target_arg
            return True
        if arg_kind == "KeyList":
            if not isinstance(target_arg, list):
                return False
            if not all(isinstance(k, KeyExpression) and k.is_plain() for k in target_arg):
                return False
            bindings[parg.name] = list(target_arg)
            return True
        if arg_kind == "Sub":
            bindings[parg.name] = target_arg
            return True
        if arg_kind == "Tree":
            if target_arg is None:
                bindings[parg.name] = []
            else:
                bindings[parg.name] = [
                    classify_as_tapleaf(leaf) for leaf in target_arg.tapleaves()
                ]
            return True
        return False
    if isinstance(parg, PatMusig):
        if arg_kind != "Key":
            return False
        if not isinstance(target_arg, KeyExpression) or not target_arg.is_musig():
            return False
        indices = target_arg.musig_key_indices() or ()
        keys = [KeyExpression.plain(i, target_arg.num1, target_arg.num2) for i in indices]
        bindings[parg.threshold] = len(keys)
        bindings[parg.keys] = keys
        return True
    if isinstance(parg, PatSub):
        if not isinstance(target_arg, DescriptorTemplate):
            return False
        cur = target_arg
        for w in parg.wrappers:
            if cur.kind != w:
                return False
            cur = cur.args[0]
        return _match_pattern(parg.inner, cur, bindings)
    return False


def _match_pattern(
    pattern: Pattern, target: DescriptorTemplate, bindings: Dict[str, Any]
) -> bool:
    variant = _KEYWORD_TO_VARIANT[pattern.keyword]
    if target.kind != variant:
        return False
    arg_kinds = VARIANT_ARG_KINDS[variant]
    # `thresh` has a variable-length second arg in the AST (Vec<DT>) but no
    # cleartext spec entry uses it, so no special handling is needed here.
    if len(pattern.args) != len(target.args):
        return False
    for parg, targ, ak in zip(pattern.args, target.args, arg_kinds):
        if not _match_arg(parg, targ, ak, bindings):
            return False
    return True


def _try_match(entry: Entry, target: DescriptorTemplate) -> Optional[Dict[str, Any]]:
    for pat in entry.patterns:
        bindings: Dict[str, Any] = {}
        if _match_pattern(pat, target, bindings):
            return bindings
    return None


def classify(target: DescriptorTemplate) -> _ClassInstance:
    for entry in TOP_LEVEL_SPECS:
        b = _try_match(entry, target)
        if b is None:
            continue
        fields: Dict[str, Any] = {}
        for fname in entry.field_order:
            fields[fname] = b.get(fname)
        return _ClassInstance(name=entry.name, fields=fields)
    return _ClassInstance(name="Other")


def classify_as_tapleaf(target: DescriptorTemplate) -> _ClassInstance:
    for entry in TAPLEAF_SPECS:
        b = _try_match(entry, target)
        if b is None:
            continue
        fields: Dict[str, Any] = {}
        for fname in entry.field_order:
            fields[fname] = b.get(fname)
        return _ClassInstance(name=entry.name, fields=fields)
    return _ClassInstance(name="Other", other_str=str(target))


# ---------------------------------------------------------------------------
# Display ordering for tapleaves (replaces Rust's TapleafClass::display_cmp)
# ---------------------------------------------------------------------------


def _key_sort_key(k: KeyExpression) -> tuple:
    if k.is_plain():
        return (0, k.plain_key_index())
    indices = k.musig_key_indices() or ()
    return (1, len(indices), tuple(indices))


def _leaf_sort_key(leaf: _ClassInstance) -> tuple:
    if leaf.name == "Other":
        order = len(TAPLEAF_SPECS)
        return (order, leaf.other_str or "")
    entry = _TAPLEAF_BY_NAME[leaf.name]
    order = _TAPLEAF_ORDER[leaf.name]
    parts: List[Any] = [order]
    f = leaf.fields
    # Multikey tie-break: number of keys, then threshold.
    if "keys" in entry.field_kinds:
        parts.append(len(f["keys"]))
    if "threshold" in entry.field_kinds:
        parts.append(f["threshold"])
    # Then individual key sort keys.
    for name in ("key", "key1", "key2"):
        if name in entry.field_kinds:
            parts.append(_key_sort_key(f[name]))
    # Then numeric lock fields.
    for name in ("blocks", "relative_time", "block_height", "timestamp"):
        if name in entry.field_kinds:
            parts.append(f[name])
    return tuple(parts)


# ---------------------------------------------------------------------------
# Forward rendering (class → cleartext string)
# ---------------------------------------------------------------------------


def _format_key(kp: KeyExpression, canonical: bool) -> str:
    if canonical:
        if kp.is_plain():
            return f"@{kp.plain_key_index()}"
        indices = kp.musig_key_indices() or ()
        return "musig(" + ",".join(f"@{i}" for i in indices) + ")"
    if kp.is_plain():
        return f"@{kp.plain_key_index()}/<{kp.num1};{kp.num2}>/*"
    indices = kp.musig_key_indices() or ()
    return (
        "musig(" + ",".join(f"@{i}" for i in indices) + f")/<{kp.num1};{kp.num2}>/*"
    )


def _format_key_indices(keys: Sequence[KeyExpression], canonical: bool) -> str:
    if not keys:
        return ""
    if len(keys) == 1:
        return _format_key(keys[0], canonical)
    init = ", ".join(_format_key(k, canonical) for k in keys[:-1])
    return f"{init} and {_format_key(keys[-1], canonical)}"


def _format_relative_time(time: int) -> str:
    return format_seconds((time & ~SEQUENCE_LOCKTIME_TYPE_FLAG) * 512)


def _format_token(tok: CleartextToken, value: Any, canonical: bool) -> str:
    if tok.kind == "Key":
        return _format_key(value, canonical)
    if tok.kind == "KeyList":
        return _format_key_indices(value, canonical)
    if tok.kind == "Threshold":
        return str(value)
    if tok.kind == "Blocks":
        return str(value)
    if tok.kind == "RelativeTime":
        return _format_relative_time(value)
    if tok.kind == "BlockHeight":
        return str(value)
    if tok.kind == "Timestamp":
        return format_utc_date(value)
    raise AssertionError(f"unhandled cleartext kind {tok.kind!r}")


def _render(entry: Entry, fields: Dict[str, Any], canonical: bool) -> str:
    out: List[str] = []
    for tok in entry.cleartext_tokens:
        if tok.is_literal:
            out.append(tok.text)
        else:
            out.append(_format_token(tok, fields[tok.name], canonical))
    return "".join(out)


# ---------------------------------------------------------------------------
# Score helpers
# ---------------------------------------------------------------------------


def _entry_score(entry: Entry, fields: Dict[str, Any]) -> int:
    score = entry.plain_pattern_count
    if entry.musig_pattern_count > 0:
        keys = fields.get("keys")
        threshold = fields.get("threshold")
        if isinstance(keys, list) and threshold is not None and threshold == len(keys):
            score += entry.musig_pattern_count
    return score


def _outer_score(cls: _ClassInstance) -> int:
    if cls.name == "Other":
        return 1
    entry = _TOP_LEVEL_BY_NAME[cls.name]
    return _entry_score(entry, cls.fields)


def _per_leaf_score(leaf: _ClassInstance) -> int:
    if leaf.name == "Other":
        return 1
    entry = _TAPLEAF_BY_NAME[leaf.name]
    return _entry_score(entry, leaf.fields)


# ---------------------------------------------------------------------------
# Canonical-derivation check + factorial-product helper
# ---------------------------------------------------------------------------


def _are_key_derivations_canonical(dt: DescriptorTemplate) -> bool:
    by_key: Dict[Tuple, List[Tuple[int, int]]] = {}
    for kp, _ in dt.placeholders():
        by_key.setdefault(kp.key_type, []).append((kp.num1, kp.num2))
    for pairs in by_key.values():
        pairs.sort()
        for i, (n1, n2) in enumerate(pairs):
            if (n1, n2) != (2 * i, 2 * i + 1):
                return False
    return True


def _key_derivation_orderings_count(dt: DescriptorTemplate) -> int:
    counts: Dict[Tuple, int] = {}
    for kp, _ in dt.placeholders():
        counts[kp.key_type] = counts.get(kp.key_type, 0) + 1
    product = 1
    for k in counts.values():
        f = 1
        for i in range(1, k + 1):
            f = _sat_mul(f, i)
        product = _sat_mul(product, f)
    return product


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def confusion_score(dt: DescriptorTemplate) -> int:
    cls = classify(dt)
    if cls.name in ("Taproot", "TaprootMusig"):
        score = _outer_score(cls)
        leaves: List[_ClassInstance] = cls.fields.get("leaves", [])
        n_leaves = len(leaves)
        for leaf in leaves:
            score = _sat_mul(score, _per_leaf_score(leaf))
        if n_leaves > 1:
            i = 1
            while i <= 2 * n_leaves - 3:
                score = _sat_mul(score, i)
                i += 2
        base = score
    else:
        base = _outer_score(cls)
    return _sat_mul(base, _key_derivation_orderings_count(dt))


def to_cleartext(dt: DescriptorTemplate) -> Tuple[List[str], bool]:
    """Return (`descriptions`, `has_cleartext`).

    `descriptions[0]` is the top-level (or key-path) description; the
    rest are tap-tree leaf descriptions in canonical display order.
    `has_cleartext` is True iff every part of the descriptor was
    classified into a recognized cleartext form.
    """
    if not _are_key_derivations_canonical(dt):
        return [str(dt)], False
    cls = classify(dt)
    if cls.name == "Other":
        return [str(dt)], False
    if cls.name in ("Taproot", "TaprootMusig"):
        entry = _TOP_LEVEL_BY_NAME[cls.name]
        primary = _render(entry, cls.fields, canonical=True)
        leaves: List[_ClassInstance] = list(cls.fields.get("leaves", []))
        leaves.sort(key=_leaf_sort_key)
        descriptions = [primary]
        all_have_cleartext = True
        for leaf in leaves:
            if leaf.name == "Other":
                descriptions.append(leaf.other_str or "")
                all_have_cleartext = False
            else:
                leaf_entry = _TAPLEAF_BY_NAME[leaf.name]
                descriptions.append(_render(leaf_entry, leaf.fields, canonical=True))
        return descriptions, all_have_cleartext
    # Non-taproot top-level.
    entry = _TOP_LEVEL_BY_NAME[cls.name]
    return [_render(entry, cls.fields, canonical=True)], True
