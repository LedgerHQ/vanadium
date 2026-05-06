//! Build script: generates `cleartext_generated.rs` from `cleartext.spec.toml`.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Spec deserialization
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Spec {
    #[serde(default)]
    top_level: Vec<Entry>,
    #[serde(default)]
    tapleaf: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
    patterns: Vec<String>,
    cleartext: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pattern AST
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Pattern {
    keyword: String,
    args: Vec<PatternArg>,
}

#[derive(Clone, Debug)]
enum PatternArg {
    /// `$name` — a normal binding.
    Binding { name: String, kind: BindingKind },
    /// `musig($threshold, $keys)` — only valid in a Key position. The two
    /// inner bindings are always Threshold + KeyList by construction.
    Musig { threshold: String, keys: String },
    /// A nested pattern, optionally preceded by miniscript wrappers (e.g. `v:`).
    Sub {
        wrappers: Vec<String>,
        inner: Box<Pattern>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingKind {
    Key,
    KeyList,
    Threshold,
    Blocks,
    RelativeTime,
    BlockHeight,
    Timestamp,
    /// Bound to the `Option<TapTree>` of a `tr(...)` and lowered to
    /// `Vec<TapleafClass>` after classification.
    Leaves,
}

/// Static metadata for a binding kind: the host-language type, the matching
/// `CleartextPart` / `CleartextValue` variant name, the cursor method that
/// pops a value of this kind, and the implicit value range (if any).
struct KindInfo {
    rust_type: &'static str,
    cleartext_variant: Option<&'static str>,
    cursor_method: Option<&'static str>,
    range: Option<(u32, Option<u32>)>,
}

impl BindingKind {
    fn info(self) -> KindInfo {
        match self {
            BindingKind::Key => KindInfo {
                rust_type: "KeyPlaceholder",
                cleartext_variant: Some("KeyIndex"),
                cursor_method: Some("key_index"),
                range: None,
            },
            BindingKind::KeyList => KindInfo {
                rust_type: "Vec<KeyPlaceholder>",
                cleartext_variant: Some("KeyIndices"),
                cursor_method: Some("key_indices"),
                range: None,
            },
            BindingKind::Threshold => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("Threshold"),
                cursor_method: Some("threshold"),
                range: None,
            },
            BindingKind::Blocks => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("Blocks"),
                cursor_method: Some("blocks"),
                range: Some((1, Some(65_536))),
            },
            BindingKind::RelativeTime => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("RelativeTime"),
                cursor_method: Some("relative_time"),
                range: Some((4_194_305, Some(4_259_840))),
            },
            BindingKind::BlockHeight => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("BlockHeight"),
                cursor_method: Some("block_height"),
                range: Some((1, Some(500_000_000))),
            },
            BindingKind::Timestamp => KindInfo {
                rust_type: "u32",
                cleartext_variant: Some("Timestamp"),
                cursor_method: Some("timestamp"),
                range: Some((500_000_000, None)),
            },
            BindingKind::Leaves => KindInfo {
                rust_type: "Vec<TapleafClass>",
                cleartext_variant: None,
                cursor_method: None,
                range: None,
            },
        }
    }
}

/// Map a binding name to its kind. Trailing digits are stripped so `$key`,
/// `$key1`, `$key2` all share kind Key.
fn binding_name_kind(name: &str) -> Option<BindingKind> {
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    Some(match base {
        "key" | "internal_key" => BindingKind::Key,
        "keys" => BindingKind::KeyList,
        "threshold" => BindingKind::Threshold,
        "blocks" => BindingKind::Blocks,
        "relative_time" => BindingKind::RelativeTime,
        "block_height" => BindingKind::BlockHeight,
        "timestamp" => BindingKind::Timestamp,
        "leaves" => BindingKind::Leaves,
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Descriptor-AST tables (mirror of the runtime AST in `bip388::mod`).
// ---------------------------------------------------------------------------

fn keyword_to_variant(kw: &str) -> Option<&'static str> {
    Some(match kw {
        "sh" => "Sh",
        "wsh" => "Wsh",
        "pkh" => "Pkh",
        "wpkh" => "Wpkh",
        "sortedmulti" => "Sortedmulti",
        "sortedmulti_a" => "Sortedmulti_a",
        "tr" => "Tr",
        "pk" => "Pk",
        "pk_k" => "Pk_k",
        "pk_h" => "Pk_h",
        "older" => "Older",
        "after" => "After",
        "andor" => "Andor",
        "and_v" => "And_v",
        "and_b" => "And_b",
        "and_n" => "And_n",
        "or_b" => "Or_b",
        "or_c" => "Or_c",
        "or_d" => "Or_d",
        "or_i" => "Or_i",
        "thresh" => "Thresh",
        "multi" => "Multi",
        "multi_a" => "Multi_a",
        _ => return None,
    })
}

fn wrapper_to_variant(c: char) -> Option<&'static str> {
    Some(match c {
        'a' => "A",
        's' => "S",
        'c' => "C",
        't' => "T",
        'd' => "D",
        'v' => "V",
        'j' => "J",
        'n' => "N",
        'l' => "L",
        'u' => "U",
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArgKind {
    Key,
    Num,
    KeyList,
    Sub,
    /// Special: the second argument of `tr(...)` — `Option<TapTree>` lowered
    /// to a `Vec<TapleafClass>`.
    Tree,
}

fn variant_arg_kinds(variant: &str) -> &'static [ArgKind] {
    use ArgKind::*;
    match variant {
        "Pk" | "Pk_k" | "Pk_h" | "Pkh" | "Wpkh" => &[Key],
        "Older" | "After" => &[Num],
        "Multi" | "Multi_a" | "Sortedmulti" | "Sortedmulti_a" => &[Num, KeyList],
        "Tr" => &[Key, Tree],
        "And_v" | "And_b" | "And_n" | "Or_b" | "Or_c" | "Or_d" | "Or_i" => &[Sub, Sub],
        "Andor" => &[Sub, Sub, Sub],
        "Sh" | "Wsh" | "A" | "S" | "C" | "T" | "D" | "V" | "J" | "N" | "L" | "U" => &[Sub],
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Pattern parser (recursive descent over the spec-language pattern syntax).
//
// Grammar:
//
//   Pattern    := Ident '(' Args? ')' | Ident
//   Args       := Arg (',' Arg)*
//   Arg        := '$' Name                                   // binding
//               | 'musig' '(' '$' Name ',' '$' Name ')'      // only in Key
//               | (WrapperChars ':')? Pattern                // sub
//   Name       := [a-z_][a-z0-9_]*
// ---------------------------------------------------------------------------

struct PatternParser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> PatternParser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.pos).copied()
    }

    fn bump(&mut self, c: u8) -> Result<(), String> {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!(
                "expected '{}' at byte {} in {:?}",
                c as char, self.pos, self.src
            ))
        }
    }

    fn try_bump(&mut self, c: u8) -> bool {
        self.skip_ws();
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            Err(format!(
                "expected identifier at byte {} in {:?}",
                self.pos, self.src
            ))
        } else {
            Ok(self.src[start..self.pos].to_string())
        }
    }

    fn parse_binding_name(&mut self) -> Result<String, String> {
        self.bump(b'$')?;
        self.parse_ident()
    }

    fn parse_pattern(&mut self) -> Result<Pattern, String> {
        let kw = self.parse_ident()?;
        let variant = keyword_to_variant(&kw)
            .ok_or_else(|| format!("unknown descriptor keyword '{}'", kw))?;

        if !self.try_bump(b'(') {
            return Ok(Pattern {
                keyword: kw,
                args: Vec::new(),
            });
        }

        let arg_kinds = variant_arg_kinds(variant);
        let mut args = Vec::new();
        if !self.try_bump(b')') {
            loop {
                let kind = arg_kinds.get(args.len()).copied().unwrap_or(ArgKind::Sub);
                args.push(self.parse_arg(kind)?);
                self.skip_ws();
                if self.try_bump(b')') {
                    break;
                }
                self.bump(b',')?;
            }
        }
        Ok(Pattern { keyword: kw, args })
    }

    fn parse_arg(&mut self, expected: ArgKind) -> Result<PatternArg, String> {
        self.skip_ws();
        // Binding starts with '$'.
        if self.peek() == Some(b'$') {
            let name = self.parse_binding_name()?;
            let kind = binding_name_kind(&name)
                .ok_or_else(|| format!("unknown binding name '${}'", name))?;
            check_kind_matches(&name, kind, expected)?;
            return Ok(PatternArg::Binding { name, kind });
        }
        // `musig(...)` is only valid in a Key position; it's spelled like a
        // keyword so we have to peek.
        let saved = self.pos;
        if let Ok(ident) = self.parse_ident() {
            if ident == "musig" {
                if expected != ArgKind::Key {
                    return Err(format!(
                        "musig(...) is only allowed in a Key position; got {:?}",
                        expected
                    ));
                }
                self.bump(b'(')?;
                let threshold = self.parse_binding_name()?;
                if binding_name_kind(&threshold) != Some(BindingKind::Threshold) {
                    return Err(format!(
                        "first arg of musig(...) must be a $threshold binding, got '${}'",
                        threshold
                    ));
                }
                self.bump(b',')?;
                let keys = self.parse_binding_name()?;
                if binding_name_kind(&keys) != Some(BindingKind::KeyList) {
                    return Err(format!(
                        "second arg of musig(...) must be a $keys binding, got '${}'",
                        keys
                    ));
                }
                self.bump(b')')?;
                return Ok(PatternArg::Musig { threshold, keys });
            }
            // Otherwise rewind: it's a keyword for a (possibly wrapped) sub-pattern.
            self.pos = saved;
        }
        // Optional wrappers + nested pattern.
        let mut wrappers = Vec::new();
        loop {
            let snap = self.pos;
            let id = self.parse_ident().ok();
            self.skip_ws();
            if let Some(name) = id {
                if self.peek() == Some(b':') {
                    for c in name.chars() {
                        let v = wrapper_to_variant(c).ok_or_else(|| {
                            format!("unknown wrapper character '{}' in '{}'", c, name)
                        })?;
                        wrappers.push(v.to_string());
                    }
                    self.pos += 1;
                    continue;
                }
            }
            self.pos = snap;
            break;
        }
        if expected != ArgKind::Sub && !wrappers.is_empty() {
            return Err(format!(
                "wrappers are only allowed in Sub positions; got {:?}",
                expected
            ));
        }
        let inner = self.parse_pattern()?;
        Ok(PatternArg::Sub {
            wrappers,
            inner: Box::new(inner),
        })
    }
}

fn check_kind_matches(name: &str, binding: BindingKind, positional: ArgKind) -> Result<(), String> {
    match (binding, positional) {
        (BindingKind::Key, ArgKind::Key)
        | (BindingKind::KeyList, ArgKind::KeyList)
        | (
            BindingKind::Threshold
            | BindingKind::Blocks
            | BindingKind::RelativeTime
            | BindingKind::BlockHeight
            | BindingKind::Timestamp,
            ArgKind::Num,
        )
        | (BindingKind::Leaves, ArgKind::Tree) => Ok(()),
        _ => Err(format!(
            "binding '${}' (kind {:?}) doesn't match the AST position kind {:?}",
            name, binding, positional
        )),
    }
}

// ---------------------------------------------------------------------------
// Per-entry analysis: class fields, cleartext template, etc.
// ---------------------------------------------------------------------------

/// Walk a pattern, collecting (binding name, kind) pairs in source order.
/// Each `musig(...)` primitive contributes its `threshold` and `keys` bindings
/// (kinds Threshold and KeyList).
fn pattern_bindings(p: &Pattern) -> Vec<(String, BindingKind)> {
    fn walk(p: &Pattern, out: &mut Vec<(String, BindingKind)>) {
        for arg in &p.args {
            match arg {
                PatternArg::Binding { name, kind } => out.push((name.clone(), *kind)),
                PatternArg::Musig { threshold, keys } => {
                    out.push((threshold.clone(), BindingKind::Threshold));
                    out.push((keys.clone(), BindingKind::KeyList));
                }
                PatternArg::Sub { inner, .. } => walk(inner, out),
            }
        }
    }
    let mut out = Vec::new();
    walk(p, &mut out);
    out
}

fn pattern_uses_musig(p: &Pattern) -> bool {
    p.args.iter().any(|a| match a {
        PatternArg::Musig { .. } => true,
        PatternArg::Sub { inner, .. } => pattern_uses_musig(inner),
        _ => false,
    })
}

/// Class field definitions for a spec entry: the union of bindings across all
/// patterns. Within an entry, all patterns must agree on (name, kind).
struct ClassFields {
    /// Field declaration order: first occurrence across patterns.
    order: Vec<String>,
    kinds: BTreeMap<String, BindingKind>,
}

fn class_fields_for_entry(entry: &Entry, patterns: &[Pattern]) -> Result<ClassFields, String> {
    let mut order = Vec::new();
    let mut kinds: BTreeMap<String, BindingKind> = BTreeMap::new();
    for p in patterns {
        for (name, kind) in pattern_bindings(p) {
            match kinds.get(&name) {
                Some(prev) if *prev != kind => {
                    return Err(format!(
                        "entry '{}': binding '${}' has inconsistent kinds across patterns: {:?} vs {:?}",
                        entry.name, name, prev, kind
                    ));
                }
                Some(_) => {}
                None => {
                    order.push(name.clone());
                    kinds.insert(name, kind);
                }
            }
        }
    }
    Ok(ClassFields { order, kinds })
}

#[derive(Clone, Debug)]
enum CleartextToken {
    Literal(String),
    Field { name: String, kind: BindingKind },
}

fn parse_cleartext(items: &[String], fields: &ClassFields) -> Result<Vec<CleartextToken>, String> {
    let mut out = Vec::new();
    for item in items {
        if let Some(rest) = item.strip_prefix('$') {
            let kind = *fields
                .kinds
                .get(rest)
                .ok_or_else(|| format!("cleartext references unknown field '${}'", rest))?;
            if kind == BindingKind::Leaves {
                return Err(format!(
                    "cleartext cannot reference '${}' (Leaves are recursed into, not rendered)",
                    rest
                ));
            }
            out.push(CleartextToken::Field {
                name: rest.to_string(),
                kind,
            });
        } else {
            let bytes = item.as_bytes();
            if bytes.is_empty() {
                return Err("cleartext literal is empty".to_string());
            }
            if bytes[0].is_ascii_digit() {
                return Err(format!("cleartext literal {:?} starts with a digit", item));
            }
            if bytes[bytes.len() - 1].is_ascii_digit() {
                return Err(format!("cleartext literal {:?} ends with a digit", item));
            }
            if item.contains('@') {
                return Err(format!("cleartext literal {:?} contains '@'", item));
            }
            out.push(CleartextToken::Literal(item.clone()));
        }
    }
    for w in out.windows(2) {
        if let (CleartextToken::Field { .. }, CleartextToken::Field { .. }) = (&w[0], &w[1]) {
            return Err(
                "cleartext template has two adjacent dynamic fields without a literal separator"
                    .to_string(),
            );
        }
    }
    Ok(out)
}

struct ProcessedEntry {
    name: String,
    patterns: Vec<Pattern>,
    fields: ClassFields,
    cleartext: Vec<CleartextToken>,
    /// True iff the class has a `$leaves` field — i.e., classification recurses
    /// into a tap-tree.
    recurses: bool,
}

fn process_entries(entries: &[Entry]) -> Result<Vec<ProcessedEntry>, String> {
    let mut processed = Vec::new();
    for entry in entries {
        let mut patterns = Vec::new();
        for src in &entry.patterns {
            let mut p = PatternParser::new(src);
            let pat = p
                .parse_pattern()
                .map_err(|e| format!("entry '{}': pattern {:?}: {}", entry.name, src, e))?;
            p.skip_ws();
            if p.pos != src.len() {
                return Err(format!(
                    "entry '{}': pattern {:?}: trailing input at byte {}",
                    entry.name, src, p.pos
                ));
            }
            patterns.push(pat);
        }
        if patterns.is_empty() {
            return Err(format!("entry '{}': no patterns", entry.name));
        }
        let fields = class_fields_for_entry(entry, &patterns)?;
        let cleartext = parse_cleartext(&entry.cleartext, &fields)
            .map_err(|e| format!("entry '{}': {}", entry.name, e))?;
        let recurses = fields.kinds.values().any(|k| *k == BindingKind::Leaves);
        processed.push(ProcessedEntry {
            name: entry.name.clone(),
            patterns,
            fields,
            cleartext,
            recurses,
        });
    }
    Ok(processed)
}

/// Inter-entry uniqueness: each entry's literal-sequence (the concatenation
/// of its `Literal` tokens, with dynamic fields replaced by a sentinel) must
/// be unique. This is the invariant on which the runtime parser relies for
/// unambiguous reverse parsing.
fn check_cleartext_uniqueness(entries: &[ProcessedEntry], scope: &str) -> Result<(), String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for e in entries {
        let mut sig = String::new();
        for tok in &e.cleartext {
            match tok {
                CleartextToken::Literal(s) => sig.push_str(s),
                CleartextToken::Field { .. } => sig.push('\u{1}'),
            }
        }
        if let Some(prev) = seen.insert(sig.clone(), e.name.clone()) {
            return Err(format!(
                "{} entries '{}' and '{}' produce indistinguishable cleartext literal sequences",
                scope, prev, e.name
            ));
        }
    }
    Ok(())
}

/// Class-enum role: top-level (DescriptorClass) or tapleaf (TapleafClass).
#[derive(Clone, Copy)]
struct ClassKind {
    class_enum: &'static str,
    pattern_enum: &'static str,
    /// The default arm shape: `Other` vs `Other(_)`.
    other_pat: &'static str,
    /// Source expression that produces an instance of `Other`.
    other_ctor: &'static str,
}

const TOP_LEVEL: ClassKind = ClassKind {
    class_enum: "DescriptorClass",
    pattern_enum: "TopLevelPattern",
    other_pat: "DescriptorClass::Other",
    other_ctor: "DescriptorClass::Other",
};

const TAPLEAF: ClassKind = ClassKind {
    class_enum: "TapleafClass",
    pattern_enum: "TapleafPattern",
    other_pat: "TapleafClass::Other(_)",
    other_ctor: "TapleafClass::Other(<Self as alloc::string::ToString>::to_string(self))",
};

// ===========================================================================
// Code emission
// ===========================================================================

fn emit_all(top_level: &[ProcessedEntry], tapleaf: &[ProcessedEntry]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "// AUTO-GENERATED by build.rs from cleartext.spec.toml. Do not edit."
    );
    let _ = writeln!(out, "// To regenerate: edit the spec and rebuild.");
    let _ = writeln!(out);

    emit_pattern_kind_enum(&mut out, "TopLevelPattern", top_level);
    emit_pattern_kind_enum(&mut out, "TapleafPattern", tapleaf);
    emit_class_enum(
        &mut out,
        "DescriptorClass",
        top_level,
        /*has_other_string=*/ false,
    );
    emit_class_enum(
        &mut out,
        "TapleafClass",
        tapleaf,
        /*has_other_string=*/ true,
    );
    emit_specs_const(&mut out, "TOP_LEVEL_SPECS", "TopLevelPattern", top_level);
    emit_specs_const(&mut out, "TAPLEAF_SPECS", "TapleafPattern", tapleaf);

    let _ = writeln!(out, "impl DescriptorTemplate {{");
    emit_classify(&mut out, top_level, TOP_LEVEL, "classify");
    emit_classify(&mut out, tapleaf, TAPLEAF, "classify_as_tapleaf");
    let _ = writeln!(out, "}}\n");

    emit_cleartext_pattern(&mut out, top_level, TOP_LEVEL);
    emit_cleartext_pattern(&mut out, tapleaf, TAPLEAF);

    emit_tapleaf_helpers(&mut out, tapleaf);
    emit_outer_score(&mut out, top_level);

    emit_from_cleartext_pattern(&mut out, top_level, TOP_LEVEL);
    emit_from_cleartext_pattern(&mut out, tapleaf, TAPLEAF);

    emit_top_level_variants(&mut out, top_level);
    emit_tapleaf_to_descriptors(&mut out, tapleaf);

    out
}

fn emit_pattern_kind_enum(out: &mut String, name: &str, entries: &[ProcessedEntry]) {
    let _ = writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub(super) enum {} {{", name);
    for e in entries {
        let _ = writeln!(out, "    {},", e.name);
    }
    let _ = writeln!(out, "}}\n");
}

fn emit_class_enum(
    out: &mut String,
    name: &str,
    entries: &[ProcessedEntry],
    has_other_string: bool,
) {
    let _ = writeln!(out, "#[derive(Clone, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub(super) enum {} {{", name);
    for e in entries {
        if e.fields.order.is_empty() {
            let _ = writeln!(out, "    {},", e.name);
        } else {
            let _ = writeln!(out, "    {} {{", e.name);
            for fname in &e.fields.order {
                let _ = writeln!(
                    out,
                    "        {}: {},",
                    fname,
                    e.fields.kinds[fname].info().rust_type
                );
            }
            let _ = writeln!(out, "    }},");
        }
    }
    if has_other_string {
        let _ = writeln!(out, "    Other(String),");
    } else {
        let _ = writeln!(out, "    Other,");
    }
    let _ = writeln!(out, "}}\n");
}

fn emit_specs_const(
    out: &mut String,
    const_name: &str,
    pattern_enum: &str,
    entries: &[ProcessedEntry],
) {
    let _ = writeln!(
        out,
        "pub(super) const {}: &[CleartextSpec<{}>] = &[",
        const_name, pattern_enum
    );
    for e in entries {
        let _ = writeln!(out, "    CleartextSpec {{");
        let _ = writeln!(out, "        kind: {}::{},", pattern_enum, e.name);
        let parts: Vec<String> = e
            .cleartext
            .iter()
            .map(|t| match t {
                CleartextToken::Literal(s) => format!("CleartextPart::Literal({:?})", s),
                CleartextToken::Field { kind, .. } => {
                    format!(
                        "CleartextPart::{}",
                        kind.info().cleartext_variant.expect("renderable")
                    )
                }
            })
            .collect();
        let _ = writeln!(out, "        parts: &[{}],", parts.join(", "));
        let _ = writeln!(out, "    }},");
    }
    let _ = writeln!(out, "];\n");
}

// ---------------------------------------------------------------------------
// classify / classify_as_tapleaf
// ---------------------------------------------------------------------------
//
// Each pattern lowers to a chain of nested `if let` / `if` blocks that, on a
// successful match, runs an innermost block:
//
//     <preamble lets>
//     break '<label> <ClassEnum>::<Variant> { <field>: <expr>, ... };
//
// The chain is built bottom-up by `fold_steps`.

enum MatchStep {
    /// `if let DescriptorTemplate::<variant>(<temp>...) = <matchee>`.
    Variant {
        matchee: String,
        variant: String,
        temps: Vec<String>,
    },
    /// `if <expr>.is_plain()`.
    PlainKey { expr: String },
    /// `if <expr>.iter().all(|k| k.is_plain())`.
    PlainKeyList { expr: String },
    /// `if <expr>.is_musig() { let <temp> = <expr>; ... }`.
    MusigKey { expr: String, temp: String },
    /// `if <expr> >= lo && <expr> < hi` (hi is exclusive; None = open-ended).
    Range {
        expr: String,
        lo: u32,
        hi: Option<u32>,
    },
}

struct Counter(usize);
impl Counter {
    fn next(&mut self) -> String {
        let s = format!("__t{}", self.0);
        self.0 += 1;
        s
    }
}

/// Result of lowering a pattern: the destructure chain plus, for the innermost
/// block, the preamble lets and the user-binding-name → expression map that
/// fields are constructed from.
struct Lowered {
    steps: Vec<MatchStep>,
    preamble: Vec<String>,
    bindings: BTreeMap<String, String>,
}

fn lower_pattern(pat: &Pattern) -> Lowered {
    let mut counter = Counter(0);
    let mut l = Lowered {
        steps: Vec::new(),
        preamble: Vec::new(),
        bindings: BTreeMap::new(),
    };
    lower(pat, "__m".to_string(), false, &mut counter, &mut l);
    l
}

fn lower(pat: &Pattern, matchee: String, is_boxed: bool, c: &mut Counter, l: &mut Lowered) {
    let variant = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let arg_kinds = variant_arg_kinds(variant);

    let matchee_expr = if is_boxed {
        format!("{}.as_ref()", matchee)
    } else {
        matchee
    };

    let temps: Vec<String> = pat.args.iter().map(|_| c.next()).collect();
    l.steps.push(MatchStep::Variant {
        matchee: matchee_expr,
        variant: variant.to_string(),
        temps: temps.clone(),
    });

    for (i, (arg, tv)) in pat.args.iter().zip(temps.iter()).enumerate() {
        let kind = arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub);
        match arg {
            PatternArg::Binding { name, kind: bkind } => match kind {
                ArgKind::Key => {
                    l.steps.push(MatchStep::PlainKey { expr: tv.clone() });
                    l.bindings.insert(name.clone(), tv.clone());
                }
                ArgKind::Num => {
                    if let Some((lo, hi)) = bkind.info().range {
                        l.steps.push(MatchStep::Range {
                            expr: tv.clone(),
                            lo,
                            hi,
                        });
                    }
                    l.bindings.insert(name.clone(), format!("*{}", tv));
                }
                ArgKind::KeyList => {
                    l.steps.push(MatchStep::PlainKeyList { expr: tv.clone() });
                    l.bindings.insert(name.clone(), tv.clone());
                }
                ArgKind::Sub | ArgKind::Tree => {
                    l.bindings.insert(name.clone(), tv.clone());
                }
            },
            PatternArg::Musig { threshold, keys } => {
                debug_assert_eq!(kind, ArgKind::Key);
                let m = c.next();
                l.steps.push(MatchStep::MusigKey {
                    expr: tv.clone(),
                    temp: m.clone(),
                });
                let kv = c.next();
                let kt = c.next();
                // Propagate the musig's shared (num1, num2) onto each plain key.
                l.preamble.push(format!(
                    "let {kv}: alloc::vec::Vec<KeyPlaceholder> = {m}.musig_key_indices().expect(\"is_musig checked\").iter().map(|&__i| KeyPlaceholder::plain(__i, {m}.num1, {m}.num2)).collect();"
                ));
                l.preamble
                    .push(format!("let {kt}: u32 = {kv}.len() as u32;"));
                l.bindings.insert(threshold.clone(), kt);
                l.bindings.insert(keys.clone(), kv);
            }
            PatternArg::Sub { wrappers, inner } => {
                let mut current = tv.clone();
                let mut current_boxed = matches!(kind, ArgKind::Sub);
                for w in wrappers {
                    let wt = c.next();
                    let m = if current_boxed {
                        format!("{}.as_ref()", current)
                    } else {
                        current.clone()
                    };
                    l.steps.push(MatchStep::Variant {
                        matchee: m,
                        variant: w.clone(),
                        temps: vec![wt.clone()],
                    });
                    current = wt;
                    current_boxed = true;
                }
                lower(inner, current, current_boxed, c, l);
            }
        }
    }
}

fn fold_steps(steps: &[MatchStep], inner: String) -> String {
    let mut code = inner;
    for step in steps.iter().rev() {
        code = match step {
            MatchStep::Variant {
                matchee,
                variant,
                temps,
            } => {
                let destructure = if temps.is_empty() {
                    format!("DescriptorTemplate::{}", variant)
                } else {
                    format!("DescriptorTemplate::{}({})", variant, temps.join(", "))
                };
                format!("if let {} = {} {{\n{}\n}}", destructure, matchee, code)
            }
            MatchStep::PlainKey { expr } => format!("if {}.is_plain() {{\n{}\n}}", expr, code),
            MatchStep::PlainKeyList { expr } => format!(
                "if {}.iter().all(|__k| __k.is_plain()) {{\n{}\n}}",
                expr, code
            ),
            MatchStep::MusigKey { expr, temp } => {
                format!("if {expr}.is_musig() {{\n    let {temp} = {expr};\n{code}\n}}")
            }
            MatchStep::Range { expr, lo, hi } => match hi {
                Some(h) => format!(
                    "if *{} >= {} && *{} < {} {{\n{}\n}}",
                    expr, lo, expr, h, code
                ),
                None => format!("if *{} >= {} {{\n{}\n}}", expr, lo, code),
            },
        };
    }
    code
}

fn build_innermost(
    l: &Lowered,
    fields: &ClassFields,
    ck: ClassKind,
    variant: &str,
    label: &str,
) -> String {
    let mut body = String::new();
    for stmt in &l.preamble {
        body.push_str(stmt);
        body.push('\n');
    }
    if fields.order.is_empty() {
        let _ = write!(body, "break '{} {}::{};", label, ck.class_enum, variant);
    } else {
        let _ = write!(body, "break '{} {}::{} {{", label, ck.class_enum, variant);
        for fname in &fields.order {
            let kind = fields.kinds[fname];
            let bound = l.bindings.get(fname).expect("binding present");
            let value = match kind {
                BindingKind::Key | BindingKind::KeyList => format!("{}.clone()", bound),
                BindingKind::Threshold
                | BindingKind::Blocks
                | BindingKind::RelativeTime
                | BindingKind::BlockHeight
                | BindingKind::Timestamp => bound.clone(),
                BindingKind::Leaves => tree_to_leaves_expr(bound),
            };
            let _ = write!(body, " {}: {},", fname, value);
        }
        body.push_str(" };");
    }
    body
}

/// Expression that converts a bound `Option<TapTree>` into `Vec<TapleafClass>`.
fn tree_to_leaves_expr(tree_expr: &str) -> String {
    format!(
        "{}.as_ref().map(tree_to_leaves).unwrap_or_default()",
        tree_expr
    )
}

fn emit_classify(out: &mut String, entries: &[ProcessedEntry], ck: ClassKind, fn_name: &str) {
    let _ = writeln!(out, "    fn {}(&self) -> {} {{", fn_name, ck.class_enum);
    let _ = writeln!(out, "        '{}: {{", fn_name);
    let _ = writeln!(out, "            let __m: &DescriptorTemplate = self;");
    for entry in entries {
        for pat in &entry.patterns {
            let l = lower_pattern(pat);
            let inner = build_innermost(&l, &entry.fields, ck, &entry.name, fn_name);
            let block = fold_steps(&l.steps, inner);
            let _ = writeln!(out, "{}", block);
        }
    }
    let _ = writeln!(out, "            {}", ck.other_ctor);
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
}

// ---------------------------------------------------------------------------
// cleartext_pattern (forward: class -> (PatternKind, Vec<CleartextValue>))
// ---------------------------------------------------------------------------

fn emit_cleartext_pattern(out: &mut String, entries: &[ProcessedEntry], ck: ClassKind) {
    let _ = writeln!(out, "impl {} {{", ck.class_enum);
    let _ = writeln!(
        out,
        "    fn cleartext_pattern(&self) -> Option<({}, alloc::vec::Vec<CleartextValue>)> {{",
        ck.pattern_enum
    );
    let _ = writeln!(out, "        match self {{");
    for entry in entries {
        let referenced: Vec<&str> = entry
            .cleartext
            .iter()
            .filter_map(|t| match t {
                CleartextToken::Field { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        let pat = match (entry.fields.order.is_empty(), referenced.is_empty()) {
            (true, _) => String::new(),
            (false, true) => " { .. }".to_string(),
            (false, false) => format!(" {{ {}, .. }}", referenced.join(", ")),
        };
        let _ = writeln!(
            out,
            "            {}::{}{} => Some(({}::{}, alloc::vec![",
            ck.class_enum, entry.name, pat, ck.pattern_enum, entry.name
        );
        for tok in &entry.cleartext {
            if let CleartextToken::Field { name, kind } = tok {
                let info = kind.info();
                let ctor = info.cleartext_variant.expect("renderable");
                let arg = match kind {
                    BindingKind::Key | BindingKind::KeyList => format!("{}.clone()", name),
                    _ => format!("*{}", name),
                };
                let _ = writeln!(out, "                CleartextValue::{}({}),", ctor, arg);
            }
        }
        let _ = writeln!(out, "            ])),");
    }
    let _ = writeln!(out, "            {} => None,", ck.other_pat);
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

// ---------------------------------------------------------------------------
// TapleafClass::order + TapleafClass::per_leaf_score + DescriptorClass::outer_score
// ---------------------------------------------------------------------------

fn emit_tapleaf_helpers(out: &mut String, tapleaf: &[ProcessedEntry]) {
    let _ = writeln!(out, "impl TapleafClass {{");
    let _ = writeln!(out, "    fn order(&self) -> u32 {{");
    let _ = writeln!(out, "        match self {{");
    for (i, e) in tapleaf.iter().enumerate() {
        let pat = if e.fields.order.is_empty() {
            ""
        } else {
            " { .. }"
        };
        let _ = writeln!(out, "            TapleafClass::{}{} => {},", e.name, pat, i);
    }
    let _ = writeln!(
        out,
        "            TapleafClass::Other(_) => {},",
        tapleaf.len()
    );
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}\n");

    let _ = writeln!(out, "    fn per_leaf_score(&self) -> u64 {{");
    let _ = writeln!(out, "        match self {{");
    for entry in tapleaf {
        emit_score_arm(out, entry, "TapleafClass", /*owned=*/ false);
    }
    let _ = writeln!(out, "            TapleafClass::Other(_) => 1,");
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

fn emit_outer_score(out: &mut String, top_level: &[ProcessedEntry]) {
    let _ = writeln!(out, "impl DescriptorClass {{");
    let _ = writeln!(out, "    fn outer_score(&self) -> u64 {{");
    let _ = writeln!(out, "        match self {{");
    for entry in top_level {
        emit_score_arm(out, entry, "DescriptorClass", /*owned=*/ false);
    }
    let _ = writeln!(out, "            DescriptorClass::Other => 1,");
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

/// Emit one match arm of `per_leaf_score()` / `outer_score()`. Score equals the
/// number of patterns whose round-trip applies: non-musig patterns always do,
/// musig patterns require `threshold == len(keys)` (the keys are guaranteed
/// plain by classification).
fn emit_score_arm(out: &mut String, entry: &ProcessedEntry, class_enum: &str, owned: bool) {
    let plain_count = entry
        .patterns
        .iter()
        .filter(|p| !pattern_uses_musig(p))
        .count() as u64;
    let musig_count = entry
        .patterns
        .iter()
        .filter(|p| pattern_uses_musig(p))
        .count() as u64;

    let pat = if entry.fields.order.is_empty() {
        String::new()
    } else if musig_count > 0 {
        " { threshold, keys, .. }".to_string()
    } else {
        " { .. }".to_string()
    };

    let body = if musig_count == 0 {
        format!("{}", plain_count)
    } else {
        // `threshold` is &u32 in borrowed (`&self`) destructures, u32 in owned.
        let t = if owned { "threshold" } else { "*threshold" };
        let extra = if musig_count == 1 {
            format!("if {} as usize == keys.len() {{ 1 }} else {{ 0 }}", t)
        } else {
            format!(
                "if {} as usize == keys.len() {{ {} }} else {{ 0 }}",
                t, musig_count
            )
        };
        format!("{} + {}", plain_count, extra)
    };
    let _ = writeln!(
        out,
        "            {}::{}{} => {},",
        class_enum, entry.name, pat, body
    );
}

// ---------------------------------------------------------------------------
// from_cleartext_pattern (reverse: (PatternKind, Vec<CleartextValue>) -> class)
// ---------------------------------------------------------------------------

fn emit_from_cleartext_pattern(out: &mut String, entries: &[ProcessedEntry], ck: ClassKind) {
    let _ = writeln!(out, "#[cfg(any(test, feature = \"cleartext-decode\"))]");
    let _ = writeln!(out, "impl {} {{", ck.class_enum);
    let _ = writeln!(
        out,
        "    fn from_cleartext_pattern(kind: {}, values: alloc::vec::Vec<CleartextValue>) -> Option<Self> {{",
        ck.pattern_enum
    );
    let _ = writeln!(
        out,
        "        let mut __cur = CleartextValueCursor::new(values);"
    );
    let _ = writeln!(out, "        let __res = match kind {{");
    for entry in entries {
        emit_from_cleartext_arm(out, entry, ck);
    }
    let _ = writeln!(out, "        }};");
    let _ = writeln!(out, "        __cur.finish()?;");
    let _ = writeln!(out, "        __res");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

fn emit_from_cleartext_arm(out: &mut String, entry: &ProcessedEntry, ck: ClassKind) {
    let _ = writeln!(out, "            {}::{} => {{", ck.pattern_enum, entry.name);
    let mut popped: BTreeMap<String, ()> = BTreeMap::new();
    for tok in &entry.cleartext {
        if let CleartextToken::Field { name, kind } = tok {
            let method = kind
                .info()
                .cursor_method
                .expect("cleartext-rendered kinds have a cursor method");
            let _ = writeln!(out, "                let {} = __cur.{}()?;", name, method);
            popped.insert(name.clone(), ());
        }
    }
    if entry.fields.order.is_empty() {
        let _ = writeln!(
            out,
            "                Some({}::{})",
            ck.class_enum, entry.name
        );
    } else {
        let _ = writeln!(
            out,
            "                Some({}::{} {{",
            ck.class_enum, entry.name
        );
        for name in &entry.fields.order {
            let kind = entry.fields.kinds[name];
            if popped.contains_key(name) {
                let _ = writeln!(out, "                    {},", name);
            } else {
                // The only field not in cleartext is `$leaves`; it's filled in
                // by the caller (`parse_top_level_candidates`) via Cartesian
                // product over per-leaf candidates, so we initialize it empty.
                debug_assert_eq!(kind, BindingKind::Leaves);
                let _ = writeln!(out, "                    {}: alloc::vec::Vec::new(),", name);
            }
        }
        let _ = writeln!(out, "                }})");
    }
    let _ = writeln!(out, "            }},");
}

// ---------------------------------------------------------------------------
// top_level_variants + tapleaf_to_descriptors (reverse construction)
// ---------------------------------------------------------------------------

fn emit_top_level_variants(out: &mut String, top_level: &[ProcessedEntry]) {
    let _ = writeln!(out, "#[cfg(any(test, feature = \"cleartext-decode\"))]");
    let _ = writeln!(
        out,
        "fn top_level_variants(class: DescriptorClass) -> Result<alloc::boxed::Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextDecodeError> {{"
    );
    let _ = writeln!(out, "    match class {{");
    for entry in top_level {
        emit_top_level_variants_arm(out, entry);
    }
    let _ = writeln!(
        out,
        "        DescriptorClass::Other => Err(CleartextDecodeError::UnrecognizedPattern),"
    );
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

fn emit_top_level_variants_arm(out: &mut String, entry: &ProcessedEntry) {
    // Destructure only fields the body actually references. For recursing
    // entries we always need `leaves`; non-musig recursing entries also need
    // `internal_key`; musig recursing entries need `keys`.
    let used: Vec<&str> = if entry.recurses {
        let mut v = vec!["leaves"];
        if entry.fields.kinds.contains_key("internal_key") {
            v.push("internal_key");
        } else {
            v.push("keys");
        }
        v
    } else {
        // Non-recursing: we destructure into named bindings used by the
        // construction of each pattern. For simplicity reference all fields
        // by name (small classes; warnings stay clean because each name is
        // used in at least one pattern's reverse construction).
        entry.fields.order.iter().map(|s| s.as_str()).collect()
    };
    let pat = if entry.fields.order.is_empty() {
        String::new()
    } else if entry.recurses {
        format!(" {{ {}, .. }}", used.join(", "))
    } else {
        format!(" {{ {} }}", used.join(", "))
    };
    let _ = writeln!(out, "        DescriptorClass::{}{} => {{", entry.name, pat);

    if entry.recurses {
        let _ = writeln!(out, "            let mut __per_leaf_variants: alloc::vec::Vec<alloc::vec::Vec<DescriptorTemplate>> = alloc::vec::Vec::new();");
        let _ = writeln!(out, "            for __leaf in &leaves {{");
        let _ = writeln!(
            out,
            "                __per_leaf_variants.push(tapleaf_to_descriptors(__leaf)?);"
        );
        let _ = writeln!(out, "            }}");
        emit_internal_key_local(out, entry);
        let _ = writeln!(out, "            if leaves.is_empty() {{");
        let _ = writeln!(out, "                return Ok(alloc::boxed::Box::new(core::iter::once(DescriptorTemplate::Tr(__internal_key, None))));");
        let _ = writeln!(out, "            }}");
        let _ = writeln!(
            out,
            "            let __trees = enumerate_taptrees(__per_leaf_variants);"
        );
        let _ = writeln!(
            out,
            "            Ok(alloc::boxed::Box::new(__trees.map(move |__t| {{"
        );
        let _ = writeln!(out, "                let mut __dt = DescriptorTemplate::Tr(__internal_key.clone(), Some(__t));");
        let _ = writeln!(out, "                canonicalize_derivations(&mut __dt);");
        let _ = writeln!(out, "                __dt");
        let _ = writeln!(out, "            }})))");
    } else {
        emit_pattern_construction_block(out, entry, /*owned=*/ true);
        let _ = writeln!(
            out,
            "            Ok(alloc::boxed::Box::new(__out.into_iter()))"
        );
    }
    let _ = writeln!(out, "        }},");
}

fn emit_tapleaf_to_descriptors(out: &mut String, tapleaf: &[ProcessedEntry]) {
    let _ = writeln!(out, "#[cfg(any(test, feature = \"cleartext-decode\"))]");
    let _ = writeln!(
        out,
        "fn tapleaf_to_descriptors(leaf: &TapleafClass) -> Result<alloc::vec::Vec<DescriptorTemplate>, CleartextDecodeError> {{"
    );
    let _ = writeln!(out, "    match leaf {{");
    for entry in tapleaf {
        let pat = if entry.fields.order.is_empty() {
            String::new()
        } else {
            format!(
                " {{ {} }}",
                entry
                    .fields
                    .order
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let _ = writeln!(out, "        TapleafClass::{}{} => {{", entry.name, pat);
        emit_pattern_construction_block(out, entry, /*owned=*/ false);
        let _ = writeln!(out, "            Ok(__out)");
        let _ = writeln!(out, "        }},");
    }
    let _ = writeln!(out, "        TapleafClass::Other(__s) => {{");
    let _ = writeln!(out, "            let dt = <DescriptorTemplate as core::str::FromStr>::from_str(__s).map_err(|e| CleartextDecodeError::InvalidDescriptor(alloc::format!(\"{{:?}}\", e)))?;");
    let _ = writeln!(out, "            Ok(alloc::vec![dt])");
    let _ = writeln!(out, "        }},");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}\n");
}

/// Materialize `__internal_key` for a recursing entry. For Taproot the field
/// is named `internal_key` directly; for TaprootMusig it's reconstructed from
/// `(threshold, keys)`.
fn emit_internal_key_local(out: &mut String, entry: &ProcessedEntry) {
    if entry.fields.kinds.contains_key("internal_key") {
        let _ = writeln!(out, "            let __internal_key = internal_key;");
    } else {
        debug_assert!(entry.fields.kinds.contains_key("keys"));
        let _ = writeln!(out, "            let __key_indices: alloc::vec::Vec<u32> = keys.iter().map(|__k| __k.plain_key_index().expect(\"plain key\")).collect();");
        let _ = writeln!(
            out,
            "            let __num1 = keys.first().map(|__k| __k.num1).unwrap_or(0);"
        );
        let _ = writeln!(
            out,
            "            let __num2 = keys.first().map(|__k| __k.num2).unwrap_or(1);"
        );
        let _ = writeln!(out, "            let __internal_key = KeyPlaceholder::musig(__key_indices, __num1, __num2);");
    }
}

/// Emit the body of a non-recursing arm: build a `__out: Vec<DescriptorTemplate>`
/// containing one entry per applicable pattern. `owned` controls whether
/// numeric class fields are bound by value (`u32`) or by reference (`&u32`),
/// which only affects the generated deref form.
fn emit_pattern_construction_block(out: &mut String, entry: &ProcessedEntry, owned: bool) {
    let _ = writeln!(
        out,
        "            let mut __out: alloc::vec::Vec<DescriptorTemplate> = alloc::vec::Vec::new();"
    );
    for pat in &entry.patterns {
        let expr = build_construction_expr(pat, owned);
        if pattern_uses_musig(pat) {
            let t = if owned { "threshold" } else { "*threshold" };
            let _ = writeln!(
                out,
                "            if {} as usize == keys.len() && keys.iter().all(|__k| __k.is_plain()) {{",
                t
            );
            let _ = writeln!(out, "                __out.push({});", expr);
            let _ = writeln!(out, "            }}");
        } else {
            let _ = writeln!(out, "            __out.push({});", expr);
        }
    }
}

fn build_construction_expr(pat: &Pattern, owned: bool) -> String {
    let variant = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let arg_kinds = variant_arg_kinds(variant);
    if pat.args.is_empty() {
        return format!("DescriptorTemplate::{}", variant);
    }
    let args: Vec<String> = pat
        .args
        .iter()
        .enumerate()
        .map(|(i, a)| build_arg_expr(a, arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub), owned))
        .collect();
    format!("DescriptorTemplate::{}({})", variant, args.join(", "))
}

fn build_arg_expr(arg: &PatternArg, kind: ArgKind, owned: bool) -> String {
    match arg {
        PatternArg::Binding { name, .. } => match kind {
            ArgKind::Key | ArgKind::KeyList => format!("{}.clone()", name),
            ArgKind::Num => {
                if owned {
                    name.clone()
                } else {
                    format!("*{}", name)
                }
            }
            ArgKind::Sub => name.clone(),
            ArgKind::Tree => "None".to_string(),
        },
        PatternArg::Musig { keys, .. } => format!(
            "KeyPlaceholder::musig({k}.iter().map(|__k| __k.plain_key_index().expect(\"plain key\")).collect(), {k}.first().map(|__k| __k.num1).unwrap_or(0), {k}.first().map(|__k| __k.num2).unwrap_or(1))",
            k = keys
        ),
        PatternArg::Sub { wrappers, inner } => {
            let mut expr = build_construction_expr(inner, owned);
            for w in wrappers.iter().rev() {
                expr = format!("DescriptorTemplate::{}(alloc::boxed::Box::new({}))", w, expr);
            }
            match kind {
                ArgKind::Sub => format!("alloc::boxed::Box::new({})", expr),
                _ => expr,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let spec_path = PathBuf::from(&manifest_dir).join("src/bip388/cleartext.spec.toml");
    println!("cargo:rerun-if-changed={}", spec_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let raw = fs::read_to_string(&spec_path)?;
    let spec: Spec = toml::from_str(&raw)?;

    let top_level = process_entries(&spec.top_level).map_err(|e| format!("top_level: {}", e))?;
    let tapleaf = process_entries(&spec.tapleaf).map_err(|e| format!("tapleaf: {}", e))?;

    check_cleartext_uniqueness(&top_level, "top_level")?;
    check_cleartext_uniqueness(&tapleaf, "tapleaf")?;

    let code = emit_all(&top_level, &tapleaf);

    let out_dir = env::var("OUT_DIR")?;
    let out_path = PathBuf::from(out_dir).join("cleartext_generated.rs");
    fs::write(&out_path, code)?;
    Ok(())
}
