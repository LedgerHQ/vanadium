#!/usr/bin/env python3
"""Code generator for the C BIP-388 implementation.

Reads `../src/cleartext/specs/cleartext.toml` (the same spec consumed by
the Rust crate's `build.rs` and the Python port) and emits a C source
file (`src/gen/cleartext_gen.c`) with the spec tables.

Also emits `src/gen/test_vectors_gen.c` from `test_vectors.toml` so the
C tests can consume the same vectors without bundling a TOML parser.
"""

from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT.parent / "src" / "cleartext" / "specs"
SPEC_PATH = SPEC_DIR / "cleartext.toml"
TEST_VECTORS_PATH = SPEC_DIR / "test_vectors.toml"
OUT_DIR = ROOT / "src" / "gen"

KEYWORD_TO_KIND = {
    "sh": "BIP388_DT_SH",
    "wsh": "BIP388_DT_WSH",
    "pkh": "BIP388_DT_PKH",
    "wpkh": "BIP388_DT_WPKH",
    "sortedmulti": "BIP388_DT_SORTEDMULTI",
    "sortedmulti_a": "BIP388_DT_SORTEDMULTI_A",
    "tr": "BIP388_DT_TR",
    "pk": "BIP388_DT_PK",
    "pk_k": "BIP388_DT_PK_K",
    "pk_h": "BIP388_DT_PK_H",
    "older": "BIP388_DT_OLDER",
    "after": "BIP388_DT_AFTER",
    "andor": "BIP388_DT_ANDOR",
    "and_v": "BIP388_DT_AND_V",
    "and_b": "BIP388_DT_AND_B",
    "and_n": "BIP388_DT_AND_N",
    "or_b": "BIP388_DT_OR_B",
    "or_c": "BIP388_DT_OR_C",
    "or_d": "BIP388_DT_OR_D",
    "or_i": "BIP388_DT_OR_I",
    "thresh": "BIP388_DT_THRESH",
    "multi": "BIP388_DT_MULTI",
    "multi_a": "BIP388_DT_MULTI_A",
}

WRAPPER_TO_KIND = {
    "a": "BIP388_DT_A", "s": "BIP388_DT_S", "c": "BIP388_DT_C", "t": "BIP388_DT_T",
    "d": "BIP388_DT_D", "v": "BIP388_DT_V", "j": "BIP388_DT_J", "n": "BIP388_DT_N",
    "l": "BIP388_DT_L", "u": "BIP388_DT_U",
}

VARIANT_ARG_KINDS = {
    "BIP388_DT_SH": ("Sub",),
    "BIP388_DT_WSH": ("Sub",),
    "BIP388_DT_PKH": ("Key",),
    "BIP388_DT_WPKH": ("Key",),
    "BIP388_DT_PK": ("Key",),
    "BIP388_DT_PK_K": ("Key",),
    "BIP388_DT_PK_H": ("Key",),
    "BIP388_DT_OLDER": ("Num",),
    "BIP388_DT_AFTER": ("Num",),
    "BIP388_DT_MULTI": ("Num", "KeyList"),
    "BIP388_DT_MULTI_A": ("Num", "KeyList"),
    "BIP388_DT_SORTEDMULTI": ("Num", "KeyList"),
    "BIP388_DT_SORTEDMULTI_A": ("Num", "KeyList"),
    "BIP388_DT_TR": ("Key", "Tree"),
    "BIP388_DT_ANDOR": ("Sub", "Sub", "Sub"),
    "BIP388_DT_AND_V": ("Sub", "Sub"),
    "BIP388_DT_AND_B": ("Sub", "Sub"),
    "BIP388_DT_AND_N": ("Sub", "Sub"),
    "BIP388_DT_OR_B": ("Sub", "Sub"),
    "BIP388_DT_OR_C": ("Sub", "Sub"),
    "BIP388_DT_OR_D": ("Sub", "Sub"),
    "BIP388_DT_OR_I": ("Sub", "Sub"),
}


def binding_kind_for_name(name: str) -> str:
    base = name.rstrip("0123456789")
    return {
        "key": "BK_KEY",
        "internal_key": "BK_KEY",
        "keys": "BK_KEYLIST",
        "threshold": "BK_THRESHOLD",
        "blocks": "BK_BLOCKS",
        "relative_time": "BK_RELATIVE_TIME",
        "block_height": "BK_BLOCK_HEIGHT",
        "timestamp": "BK_TIMESTAMP",
        "leaves": "BK_LEAVES",
    }[base]


# ---------------------------------------------------------------------------
# Pattern AST
# ---------------------------------------------------------------------------


@dataclass
class PatBinding:
    name: str
    kind: str


@dataclass
class PatMusig:
    threshold: str
    keys: str


@dataclass
class PatSub:
    wrappers: List[str]   # kind strings
    inner: "Pattern"


@dataclass
class Pattern:
    variant: str  # BIP388_DT_*
    args: List[object] = field(default_factory=list)
    uses_musig: bool = False


class PatternParser:
    def __init__(self, src: str):
        self.src = src
        self.pos = 0

    def skip(self) -> None:
        while self.pos < len(self.src) and self.src[self.pos].isspace():
            self.pos += 1

    def peek(self) -> Optional[str]:
        return self.src[self.pos] if self.pos < len(self.src) else None

    def bump(self, c: str) -> None:
        self.skip()
        if self.peek() != c:
            raise ValueError(f"expected {c!r} at {self.pos} in {self.src!r}")
        self.pos += 1

    def try_bump(self, c: str) -> bool:
        self.skip()
        if self.peek() == c:
            self.pos += 1
            return True
        return False

    def parse_ident(self) -> str:
        self.skip()
        start = self.pos
        while self.pos < len(self.src) and (self.src[self.pos].isalnum() or self.src[self.pos] == "_"):
            self.pos += 1
        if start == self.pos:
            raise ValueError(f"expected ident at {self.pos} in {self.src!r}")
        return self.src[start:self.pos]

    def parse_binding_name(self) -> str:
        self.bump("$")
        return self.parse_ident()

    def parse_pattern(self) -> Pattern:
        kw = self.parse_ident()
        variant = KEYWORD_TO_KIND.get(kw)
        if variant is None:
            raise ValueError(f"unknown keyword {kw!r}")
        pat = Pattern(variant=variant)
        if not self.try_bump("("):
            return pat
        arg_kinds = VARIANT_ARG_KINDS.get(variant, ())
        if not self.try_bump(")"):
            while True:
                ak = arg_kinds[len(pat.args)] if len(pat.args) < len(arg_kinds) else "Sub"
                pat.args.append(self.parse_arg(ak))
                self.skip()
                if self.try_bump(")"):
                    break
                self.bump(",")
        if any(isinstance(a, PatMusig) or (isinstance(a, PatSub) and a.inner.uses_musig)
               for a in pat.args):
            pat.uses_musig = True
        return pat

    def parse_arg(self, expected: str) -> object:
        self.skip()
        if self.peek() == "$":
            name = self.parse_binding_name()
            kind = binding_kind_for_name(name)
            return PatBinding(name=name, kind=kind)
        saved = self.pos
        try:
            ident = self.parse_ident()
        except ValueError:
            ident = ""
        if ident == "musig":
            if expected != "Key":
                raise ValueError(f"musig in non-Key position: {expected}")
            self.bump("(")
            t = self.parse_binding_name()
            assert binding_kind_for_name(t) == "BK_THRESHOLD"
            self.bump(",")
            k = self.parse_binding_name()
            assert binding_kind_for_name(k) == "BK_KEYLIST"
            self.bump(")")
            return PatMusig(threshold=t, keys=k)
        self.pos = saved
        wrappers: List[str] = []
        while True:
            snap = self.pos
            try:
                name = self.parse_ident()
            except ValueError:
                name = ""
            self.skip()
            if name and self.peek() == ":":
                for c in name:
                    if c not in WRAPPER_TO_KIND:
                        raise ValueError(f"unknown wrapper {c!r}")
                    wrappers.append(WRAPPER_TO_KIND[c])
                self.pos += 1
                continue
            self.pos = snap
            break
        if expected != "Sub" and wrappers:
            raise ValueError("wrappers in non-Sub position")
        inner = self.parse_pattern()
        sub = PatSub(wrappers=wrappers, inner=inner)
        if inner.uses_musig:
            pass  # propagated through Pattern.uses_musig
        return sub


def pattern_bindings(p: Pattern) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    def walk(pp: Pattern) -> None:
        for arg in pp.args:
            if isinstance(arg, PatBinding):
                out.append((arg.name, arg.kind))
            elif isinstance(arg, PatMusig):
                out.append((arg.threshold, "BK_THRESHOLD"))
                out.append((arg.keys, "BK_KEYLIST"))
            elif isinstance(arg, PatSub):
                walk(arg.inner)
    walk(p)
    return out


def pattern_uses_musig(p: Pattern) -> bool:
    for arg in p.args:
        if isinstance(arg, PatMusig):
            return True
        if isinstance(arg, PatSub) and pattern_uses_musig(arg.inner):
            return True
    return False


# ---------------------------------------------------------------------------
# Process entries
# ---------------------------------------------------------------------------


@dataclass
class Field:
    name: str
    kind: str


@dataclass
class CtToken:
    is_literal: bool
    text: str = ""
    field_name: str = ""
    kind: str = ""


@dataclass
class Entry:
    name: str
    patterns: List[Pattern]
    fields: List[Field]
    field_indices: Dict[str, int]
    cleartext: List[CtToken]
    recurses: bool
    plain_pattern_count: int
    musig_pattern_count: int


def process_entries(raw: List[dict]) -> List[Entry]:
    out: List[Entry] = []
    for r in raw:
        name = r["name"]
        patterns: List[Pattern] = []
        for s in r["patterns"]:
            pp = PatternParser(s)
            pat = pp.parse_pattern()
            pp.skip()
            if pp.pos != len(s):
                raise ValueError(f"trailing input in pattern {s!r}")
            patterns.append(pat)
        order: List[str] = []
        kinds: Dict[str, str] = {}
        for pat in patterns:
            for bname, bkind in pattern_bindings(pat):
                if bname in kinds:
                    if kinds[bname] != bkind:
                        raise ValueError(f"inconsistent kinds for ${bname}")
                else:
                    order.append(bname)
                    kinds[bname] = bkind
        field_indices = {n: i for i, n in enumerate(order)}
        fields = [Field(name=n, kind=kinds[n]) for n in order]
        tokens: List[CtToken] = []
        for item in r["cleartext"]:
            if item.startswith("$"):
                fname = item[1:]
                if fname not in kinds:
                    raise ValueError(f"unknown $-binding {fname}")
                if kinds[fname] == "BK_LEAVES":
                    raise ValueError("cleartext cannot reference $leaves")
                tokens.append(CtToken(is_literal=False, field_name=fname, kind=kinds[fname]))
            else:
                tokens.append(CtToken(is_literal=True, text=item))
        recurses = any(k == "BK_LEAVES" for k in kinds.values())
        plain_count = sum(1 for p in patterns if not pattern_uses_musig(p))
        musig_count = sum(1 for p in patterns if pattern_uses_musig(p))
        out.append(Entry(
            name=name,
            patterns=patterns,
            fields=fields,
            field_indices=field_indices,
            cleartext=tokens,
            recurses=recurses,
            plain_pattern_count=plain_count,
            musig_pattern_count=musig_count,
        ))
    return out


# ---------------------------------------------------------------------------
# Code emission
# ---------------------------------------------------------------------------


def c_str(s: str) -> str:
    # Escape backslash, double-quote; non-printable already absent from the spec.
    return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"") + '"'


def emit_pattern(buf: List[str], pat: Pattern, prefix: str, indices: Dict[str, int]) -> str:
    """Emit static const tables for `pat` and its subtrees; returns the
    name of the emitted bip388_pattern_t."""
    args_name = f"{prefix}_args"
    inner_names: List[str] = []
    wrapper_names: List[str] = []
    arg_inits: List[str] = []
    for i, arg in enumerate(pat.args):
        if isinstance(arg, PatBinding):
            arg_inits.append(
                f"    {{ .kind = PA_BINDING, .field_idx = {indices[arg.name]}, "
                f".bkind = {arg.kind}, .wrappers = NULL, .n_wrappers = 0, .inner = NULL }}"
            )
        elif isinstance(arg, PatMusig):
            arg_inits.append(
                f"    {{ .kind = PA_MUSIG, .field_idx = {indices[arg.threshold]}, "
                f".field_idx2 = {indices[arg.keys]}, .bkind = BK_NONE, "
                ".wrappers = NULL, .n_wrappers = 0, .inner = NULL }"
            )
        elif isinstance(arg, PatSub):
            sub_prefix = f"{prefix}_a{i}"
            inner_name = emit_pattern(buf, arg.inner, f"{sub_prefix}_inner", indices)
            inner_names.append(inner_name)
            if arg.wrappers:
                w_name = f"{sub_prefix}_w"
                wrapper_names.append(w_name)
                w_init = ", ".join(arg.wrappers)
                buf.append(f"static const bip388_dt_kind_t {w_name}[] = {{ {w_init} }};")
                arg_inits.append(
                    f"    {{ .kind = PA_SUB, .field_idx = 0, .bkind = BK_NONE, "
                    f".wrappers = {w_name}, .n_wrappers = {len(arg.wrappers)}, "
                    f".inner = &{inner_name} }}"
                )
            else:
                arg_inits.append(
                    f"    {{ .kind = PA_SUB, .field_idx = 0, .bkind = BK_NONE, "
                    f".wrappers = NULL, .n_wrappers = 0, .inner = &{inner_name} }}"
                )

    if arg_inits:
        buf.append(f"static const bip388_pat_arg_t {args_name}[] = {{")
        buf.append(",\n".join(arg_inits))
        buf.append("};")
    pat_name = f"{prefix}"
    args_ref = args_name if arg_inits else "NULL"
    buf.append(
        f"static const bip388_pattern_t {pat_name} = {{ .variant = {pat.variant}, "
        f".args = {args_ref}, .n_args = {len(pat.args)}, "
        f".uses_musig = {'true' if pat.uses_musig else 'false'} }};"
    )
    return pat_name


def emit_entries(buf: List[str], section: str, entries: List[Entry]) -> None:
    for ei, e in enumerate(entries):
        pat_names: List[str] = []
        for pi, pat in enumerate(e.patterns):
            pat_names.append(emit_pattern(buf, pat, f"{section}_{ei}_p{pi}", e.field_indices))
        # Per-entry array of pattern pointers
        buf.append(f"static const bip388_pattern_t *const {section}_{ei}_patterns[] = {{")
        for n in pat_names:
            buf.append(f"    &{n},")
        if not pat_names:
            buf.append("    NULL")
        buf.append("};")
        # Fields table
        buf.append(f"static const bip388_spec_field_t {section}_{ei}_fields[] = {{")
        for f in e.fields:
            buf.append(f"    {{ .name = {c_str(f.name)}, .kind = {f.kind} }},")
        if not e.fields:
            buf.append("    { .name = NULL, .kind = BK_NONE }")
        buf.append("};")
        # Cleartext template
        buf.append(f"static const bip388_ct_token_t {section}_{ei}_cleartext[] = {{")
        for t in e.cleartext:
            if t.is_literal:
                buf.append(
                    f"    {{ .kind = CT_LITERAL, .literal = {c_str(t.text)}, "
                    f".field_idx = 0, .bkind = BK_NONE }},"
                )
            else:
                buf.append(
                    f"    {{ .kind = CT_FIELD, .literal = NULL, "
                    f".field_idx = {e.field_indices[t.field_name]}, .bkind = {t.kind} }},"
                )
        buf.append("};")


def emit_specs_array(buf: List[str], section: str, entries: List[Entry], array_name: str) -> None:
    buf.append(f"const bip388_spec_entry_t {array_name}[] = {{")
    for ei, e in enumerate(entries):
        patterns_ref = f"{section}_{ei}_patterns"
        fields_ref = f"{section}_{ei}_fields" if e.fields else "NULL"
        cleartext_ref = f"{section}_{ei}_cleartext"
        buf.append("    {")
        buf.append(f"        .name = {c_str(e.name)},")
        buf.append(f"        .patterns = {patterns_ref},")
        buf.append(f"        .n_patterns = {len(e.patterns)},")
        buf.append(f"        .fields = {fields_ref},")
        buf.append(f"        .n_fields = {len(e.fields)},")
        buf.append(f"        .cleartext = {cleartext_ref},")
        buf.append(f"        .n_cleartext = {len(e.cleartext)},")
        buf.append(f"        .recurses = {'true' if e.recurses else 'false'},")
        buf.append(f"        .plain_pattern_count = {e.plain_pattern_count},")
        buf.append(f"        .musig_pattern_count = {e.musig_pattern_count},")
        buf.append("    },")
    buf.append("};")
    buf.append(f"const size_t {array_name}_count = {len(entries)};")


def generate_cleartext() -> None:
    with open(SPEC_PATH, "rb") as f:
        raw = tomllib.load(f)
    top_level = process_entries(raw.get("top_level", []))
    tapleaf = process_entries(raw.get("tapleaf", []))

    out: List[str] = []
    out.append("/* AUTO-GENERATED by tools/gen.py from src/cleartext/specs/cleartext.toml. */")
    out.append('#include "cleartext_gen.h"')
    out.append("")

    emit_entries(out, "top", top_level)
    out.append("")
    emit_entries(out, "tap", tapleaf)
    out.append("")
    emit_specs_array(out, "top", top_level, "bip388_top_level_specs")
    out.append("")
    emit_specs_array(out, "tap", tapleaf, "bip388_tapleaf_specs")
    out.append("")
    out.append("void bip388_binding_range(bip388_binding_kind_t k, uint32_t *lo, uint32_t *hi) {")
    out.append("    switch (k) {")
    out.append("        case BK_BLOCKS: *lo = 1; *hi = 65536u; return;")
    out.append("        case BK_RELATIVE_TIME: *lo = 4194305u; *hi = 4259840u; return;")
    out.append("        case BK_BLOCK_HEIGHT: *lo = 1; *hi = 500000000u; return;")
    out.append("        case BK_TIMESTAMP: *lo = 500000000u; *hi = 0; return;")
    out.append("        default: *lo = 0; *hi = 0; return;")
    out.append("    }")
    out.append("}")
    out.append("")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "cleartext_gen.c").write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------------------
# Test vectors
# ---------------------------------------------------------------------------


def generate_test_vectors() -> None:
    with open(TEST_VECTORS_PATH, "rb") as f:
        raw = tomllib.load(f)
    vectors = raw["vector"]
    out: List[str] = []
    out.append("/* AUTO-GENERATED by tools/gen.py from src/cleartext/specs/test_vectors.toml. */")
    out.append('#include "test_vectors_gen.h"')
    out.append("")
    for i, v in enumerate(vectors):
        if "cleartext" in v:
            ct = v["cleartext"]
            out.append(f"static const char *const tv_cleartext_{i}[] = {{")
            for line in ct:
                out.append(f"    {c_str(line)},")
            out.append("};")
    out.append("")
    out.append("const bip388_test_vector_t bip388_test_vectors[] = {")
    for i, v in enumerate(vectors):
        out.append("    {")
        out.append(f"        .template = {c_str(v['template'])},")
        if "confusion_score" in v:
            out.append(f"        .has_confusion_score = true,")
            out.append(f"        .confusion_score = {v['confusion_score']}ull,")
        else:
            out.append(f"        .has_confusion_score = false,")
            out.append(f"        .confusion_score = 0,")
        if "cleartext" in v:
            out.append(f"        .has_cleartext_array = true,")
            out.append(f"        .cleartext = tv_cleartext_{i},")
            out.append(f"        .n_cleartext = {len(v['cleartext'])},")
        else:
            out.append(f"        .has_cleartext_array = false,")
            out.append(f"        .cleartext = NULL,")
            out.append(f"        .n_cleartext = 0,")
        if "has_cleartext" in v:
            out.append(f"        .has_has_cleartext = true,")
            out.append(f"        .has_cleartext = {'true' if v['has_cleartext'] else 'false'},")
        else:
            out.append(f"        .has_has_cleartext = false,")
            out.append(f"        .has_cleartext = false,")
        out.append("    },")
    out.append("};")
    out.append(f"const size_t bip388_test_vectors_count = {len(vectors)};")
    out.append("")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "test_vectors_gen.c").write_text("\n".join(out) + "\n")

    header = [
        "#ifndef BIP388_TEST_VECTORS_GEN_H",
        "#define BIP388_TEST_VECTORS_GEN_H",
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    const char *template;",
        "    bool has_confusion_score;",
        "    uint64_t confusion_score;",
        "    bool has_cleartext_array;",
        "    const char *const *cleartext;",
        "    size_t n_cleartext;",
        "    bool has_has_cleartext;",
        "    bool has_cleartext;",
        "} bip388_test_vector_t;",
        "",
        "extern const bip388_test_vector_t bip388_test_vectors[];",
        "extern const size_t bip388_test_vectors_count;",
        "",
        "#endif",
        "",
    ]
    (OUT_DIR / "test_vectors_gen.h").write_text("\n".join(header))


def main() -> int:
    generate_cleartext()
    generate_test_vectors()
    print("Generated:")
    print(f"  {OUT_DIR / 'cleartext_gen.c'}")
    print(f"  {OUT_DIR / 'test_vectors_gen.c'}")
    print(f"  {OUT_DIR / 'test_vectors_gen.h'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
