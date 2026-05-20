//! Build script: generates the cleartext support files from `src/cleartext/specs/cleartext.toml`.
//!
//! Emits two files into `OUT_DIR`:
//!
//! * `cleartext_generated.rs` — always compiled. Contains class/pattern enums, the
//!   spec tables, the `classify*` and `cleartext_pattern` methods, and the score
//!   helpers used by the encoder/confusion-score paths.
//! * `cleartext_decode_generated.rs` — included only when `cleartext-decode` (or
//!   `cfg(test)`) is active. Contains the `from_cleartext_pattern` impls and the
//!   `top_level_variants` / `tapleaf_to_descriptors` reverse-construction
//!   functions.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
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
                rust_type: "KeyExpression",
                cleartext_variant: Some("KeyIndex"),
                cursor_method: Some("key_index"),
                range: None,
            },
            BindingKind::KeyList => KindInfo {
                rust_type: "Vec<KeyExpression>",
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

// ---------------------------------------------------------------------------
// Code emission
// ---------------------------------------------------------------------------
//
// The emitted file (~1100 lines of Rust) is built as one big `TokenStream`
// using `quote!` and then pretty-printed with `prettyplease`. Each section is
// produced by a small `emit_*` helper that returns its own `TokenStream`.

#[derive(Clone, Copy)]
struct ClassKind {
    class_enum: &'static str,
    pattern_enum: &'static str,
    /// True for `TapleafClass::Other(String)`; false for `DescriptorClass::Other`.
    other_has_string: bool,
}

const TOP_LEVEL: ClassKind = ClassKind {
    class_enum: "DescriptorClass",
    pattern_enum: "TopLevelPattern",
    other_has_string: false,
};

const TAPLEAF: ClassKind = ClassKind {
    class_enum: "TapleafClass",
    pattern_enum: "TapleafPattern",
    other_has_string: true,
};

impl ClassKind {
    fn class(self) -> Ident {
        format_ident!("{}", self.class_enum)
    }
    fn pattern(self) -> Ident {
        format_ident!("{}", self.pattern_enum)
    }
    fn other_pat(self) -> TokenStream {
        let c = self.class();
        if self.other_has_string {
            quote!(#c::Other(_))
        } else {
            quote!(#c::Other)
        }
    }
    fn other_ctor(self) -> TokenStream {
        let c = self.class();
        if self.other_has_string {
            quote!(#c::Other(<Self as alloc::string::ToString>::to_string(self)))
        } else {
            quote!(#c::Other)
        }
    }
}

fn id(s: &str) -> Ident {
    format_ident!("{}", s)
}

fn ts(s: &str) -> TokenStream {
    s.parse().expect("valid Rust tokens")
}

fn rust_type(k: BindingKind) -> TokenStream {
    ts(k.info().rust_type)
}

fn cleartext_variant(k: BindingKind) -> Ident {
    id(k.info().cleartext_variant.expect("renderable"))
}

fn cursor_method(k: BindingKind) -> Ident {
    id(k.info().cursor_method.expect("renderable"))
}

// ---------------------------------------------------------------------------
// classify / classify_as_tapleaf  — lower a pattern to a nested `if let` chain
// ---------------------------------------------------------------------------
//
// Each pattern lowers to a chain of nested `if let` / `if` blocks. On a
// successful match the innermost block does:
//
//     <preamble lets>
//     break '<label> <ClassEnum>::<Variant> { <field>: <expr>, ... };
//
// The chain is built bottom-up by `fold_steps`.

enum MatchStep {
    /// `if let DescriptorTemplate::<variant>(<temps>...) = <matchee>`.
    Variant {
        matchee: TokenStream,
        variant: Ident,
        temps: Vec<Ident>,
    },
    /// `if <expr>.is_plain()`.
    PlainKey { expr: Ident },
    /// `if <expr>.iter().all(|k| k.is_plain())`.
    PlainKeyList { expr: Ident },
    /// `if <expr>.is_musig() { let <temp> = <expr>; ... }`.
    MusigKey { expr: Ident, temp: Ident },
    /// `if *<expr> >= lo && *<expr> < hi` (hi exclusive; None = open-ended).
    Range {
        expr: Ident,
        lo: u32,
        hi: Option<u32>,
    },
}

struct Counter(usize);
impl Counter {
    fn next(&mut self) -> Ident {
        let s = format_ident!("__t{}", self.0);
        self.0 += 1;
        s
    }
}

struct Lowered {
    steps: Vec<MatchStep>,
    /// Statements emitted inside the innermost block before the `break`.
    preamble: Vec<TokenStream>,
    /// User-binding-name → expression used to build the class-enum field.
    bindings: BTreeMap<String, TokenStream>,
}

fn lower_pattern(pat: &Pattern) -> Lowered {
    let mut counter = Counter(0);
    let mut l = Lowered {
        steps: Vec::new(),
        preamble: Vec::new(),
        bindings: BTreeMap::new(),
    };
    lower(pat, quote!(__m), &mut counter, &mut l);
    l
}

fn lower(pat: &Pattern, matchee: TokenStream, c: &mut Counter, l: &mut Lowered) {
    let variant_str = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let variant = id(variant_str);
    let arg_kinds = variant_arg_kinds(variant_str);

    let temps: Vec<Ident> = pat.args.iter().map(|_| c.next()).collect();
    l.steps.push(MatchStep::Variant {
        matchee,
        variant,
        temps: temps.clone(),
    });

    for (i, (arg, tv)) in pat.args.iter().zip(temps.iter()).enumerate() {
        let kind = arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub);
        match arg {
            PatternArg::Binding { name, kind: bkind } => match kind {
                ArgKind::Key => {
                    l.steps.push(MatchStep::PlainKey { expr: tv.clone() });
                    l.bindings.insert(name.clone(), quote!(#tv));
                }
                ArgKind::Num => {
                    if let Some((lo, hi)) = bkind.info().range {
                        l.steps.push(MatchStep::Range {
                            expr: tv.clone(),
                            lo,
                            hi,
                        });
                    }
                    l.bindings.insert(name.clone(), quote!(*#tv));
                }
                ArgKind::KeyList => {
                    l.steps.push(MatchStep::PlainKeyList { expr: tv.clone() });
                    l.bindings.insert(name.clone(), quote!(#tv));
                }
                ArgKind::Sub | ArgKind::Tree => {
                    l.bindings.insert(name.clone(), quote!(#tv));
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
                l.preamble.push(quote! {
                    let #kv: alloc::vec::Vec<KeyExpression> = #m.musig_key_indices()
                        .expect("is_musig checked")
                        .iter()
                        .map(|&__i| KeyExpression::plain(__i, #m.num1, #m.num2))
                        .collect();
                });
                l.preamble.push(quote!(let #kt: u32 = #kv.len() as u32;));
                l.bindings.insert(threshold.clone(), quote!(#kt));
                l.bindings.insert(keys.clone(), quote!(#kv));
            }
            PatternArg::Sub { wrappers, inner } => {
                let mut current: TokenStream = quote!(#tv);
                let mut current_boxed = matches!(kind, ArgKind::Sub);
                for w in wrappers {
                    let wv = id(w);
                    let wt = c.next();
                    let m: TokenStream = if current_boxed {
                        quote!(#current.as_ref())
                    } else {
                        current.clone()
                    };
                    l.steps.push(MatchStep::Variant {
                        matchee: m,
                        variant: wv,
                        temps: vec![wt.clone()],
                    });
                    current = quote!(#wt);
                    current_boxed = true;
                }
                let next_matchee: TokenStream = if current_boxed {
                    quote!(#current.as_ref())
                } else {
                    current
                };
                lower(inner, next_matchee, c, l);
            }
        }
    }
}

fn fold_steps(steps: &[MatchStep], inner: TokenStream) -> TokenStream {
    let mut code = inner;
    for step in steps.iter().rev() {
        code = match step {
            MatchStep::Variant {
                matchee,
                variant,
                temps,
            } => {
                if temps.is_empty() {
                    quote!(if let DescriptorTemplate::#variant = #matchee { #code })
                } else {
                    quote!(if let DescriptorTemplate::#variant(#(#temps),*) = #matchee { #code })
                }
            }
            MatchStep::PlainKey { expr } => quote!(if #expr.is_plain() { #code }),
            MatchStep::PlainKeyList { expr } => {
                quote!(if #expr.iter().all(|__k| __k.is_plain()) { #code })
            }
            MatchStep::MusigKey { expr, temp } => quote! {
                if #expr.is_musig() {
                    let #temp = #expr;
                    #code
                }
            },
            MatchStep::Range { expr, lo, hi } => match hi {
                Some(h) => quote!(if *#expr >= #lo && *#expr < #h { #code }),
                None => quote!(if *#expr >= #lo { #code }),
            },
        };
    }
    code
}

fn build_innermost(
    l: &Lowered,
    fields: &ClassFields,
    ck: ClassKind,
    variant: &Ident,
    label: &TokenStream,
) -> TokenStream {
    let class = ck.class();
    let preamble = &l.preamble;
    let break_expr = if fields.order.is_empty() {
        quote!(break #label #class::#variant;)
    } else {
        let assigns = fields.order.iter().map(|fname| {
            let kind = fields.kinds[fname];
            let bound = l.bindings.get(fname).expect("binding present");
            let f = id(fname);
            let value = match kind {
                BindingKind::Key | BindingKind::KeyList => quote!(#bound.clone()),
                BindingKind::Threshold
                | BindingKind::Blocks
                | BindingKind::RelativeTime
                | BindingKind::BlockHeight
                | BindingKind::Timestamp => quote!(#bound),
                BindingKind::Leaves => {
                    quote!(#bound.as_ref().map(tree_to_leaves).unwrap_or_default())
                }
            };
            quote!(#f: #value)
        });
        quote!(break #label #class::#variant { #(#assigns),* };)
    };
    quote! {
        #(#preamble)*
        #break_expr
    }
}

fn emit_classify(entries: &[ProcessedEntry], ck: ClassKind, fn_name: &str) -> TokenStream {
    let fn_id = id(fn_name);
    let class = ck.class();
    let label: TokenStream = format!("'{fn_name}").parse().unwrap();
    let other = ck.other_ctor();

    let blocks: Vec<TokenStream> = entries
        .iter()
        .flat_map(|entry| {
            entry.patterns.iter().map(|pat| {
                let l = lower_pattern(pat);
                let variant = id(&entry.name);
                let inner = build_innermost(&l, &entry.fields, ck, &variant, &label);
                fold_steps(&l.steps, inner)
            })
        })
        .collect();

    quote! {
        fn #fn_id(&self) -> #class {
            #label: {
                let __m: &DescriptorTemplate = self;
                #(#blocks)*
                #other
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Enums and constants
// ---------------------------------------------------------------------------

fn emit_pattern_kind_enum(name: &str, entries: &[ProcessedEntry]) -> TokenStream {
    let ident = id(name);
    let variants: Vec<Ident> = entries.iter().map(|e| id(&e.name)).collect();
    quote! {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(super) enum #ident {
            #(#variants,)*
        }
    }
}

fn emit_class_enum(ck: ClassKind, entries: &[ProcessedEntry]) -> TokenStream {
    let ident = ck.class();
    let variants: Vec<TokenStream> = entries
        .iter()
        .map(|e| {
            let v = id(&e.name);
            if e.fields.order.is_empty() {
                quote!(#v)
            } else {
                let fields = e.fields.order.iter().map(|fname| {
                    let f = id(fname);
                    let ty = rust_type(e.fields.kinds[fname]);
                    quote!(#f: #ty)
                });
                quote!(#v { #(#fields),* })
            }
        })
        .collect();
    let other = if ck.other_has_string {
        quote!(Other(String))
    } else {
        quote!(Other)
    };
    quote! {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub(super) enum #ident {
            #(#variants,)*
            #other,
        }
    }
}

fn emit_specs_const(name: &str, ck: ClassKind, entries: &[ProcessedEntry]) -> TokenStream {
    let const_name = id(name);
    let pattern = ck.pattern();
    let items: Vec<TokenStream> = entries
        .iter()
        .map(|e| {
            let kind = id(&e.name);
            let parts = e.cleartext.iter().map(|t| match t {
                CleartextToken::Literal(s) => quote!(CleartextPart::Literal(#s)),
                CleartextToken::Field { kind, .. } => {
                    let v = cleartext_variant(*kind);
                    quote!(CleartextPart::#v)
                }
            });
            quote! {
                CleartextSpec {
                    kind: #pattern::#kind,
                    parts: &[#(#parts),*],
                }
            }
        })
        .collect();
    quote! {
        pub(super) const #const_name: &[CleartextSpec<#pattern>] = &[#(#items),*];
    }
}

// ---------------------------------------------------------------------------
// cleartext_pattern (forward: class -> (PatternKind, Vec<CleartextValue>))
// ---------------------------------------------------------------------------

fn emit_cleartext_pattern(entries: &[ProcessedEntry], ck: ClassKind) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    let other_pat = ck.other_pat();

    let arms: Vec<TokenStream> = entries
        .iter()
        .map(|e| {
            let variant = id(&e.name);
            let referenced: Vec<Ident> = e
                .cleartext
                .iter()
                .filter_map(|t| match t {
                    CleartextToken::Field { name, .. } => Some(id(name)),
                    _ => None,
                })
                .collect();
            let destructure: TokenStream = match (e.fields.order.is_empty(), referenced.is_empty())
            {
                (true, _) => quote!(),
                (false, true) => quote!({ .. }),
                (false, false) => quote!({ #(#referenced),*, .. }),
            };
            let values = e.cleartext.iter().filter_map(|t| match t {
                CleartextToken::Field { name, kind } => {
                    let ctor = cleartext_variant(*kind);
                    let n = id(name);
                    let arg: TokenStream = match kind {
                        BindingKind::Key | BindingKind::KeyList => quote!(#n.clone()),
                        _ => quote!(*#n),
                    };
                    Some(quote!(CleartextValue::#ctor(#arg)))
                }
                _ => None,
            });
            quote! {
                #class::#variant #destructure => {
                    Some((#pattern::#variant, alloc::vec![#(#values),*]))
                }
            }
        })
        .collect();

    quote! {
        impl #class {
            fn cleartext_pattern(&self) -> Option<(#pattern, alloc::vec::Vec<CleartextValue>)> {
                match self {
                    #(#arms,)*
                    #other_pat => None,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TapleafClass::{order,per_leaf_score} + DescriptorClass::outer_score
// ---------------------------------------------------------------------------

fn emit_tapleaf_helpers(tapleaf: &[ProcessedEntry]) -> TokenStream {
    let order_arms = tapleaf.iter().enumerate().map(|(i, e)| {
        let v = id(&e.name);
        let pat: TokenStream = if e.fields.order.is_empty() {
            quote!()
        } else {
            quote!({ .. })
        };
        let idx = i as u32;
        quote!(TapleafClass::#v #pat => #idx)
    });
    let last = tapleaf.len() as u32;
    let score_arms = tapleaf.iter().map(|e| emit_score_arm(e, "TapleafClass"));

    quote! {
        impl TapleafClass {
            fn order(&self) -> u32 {
                match self {
                    #(#order_arms,)*
                    TapleafClass::Other(_) => #last,
                }
            }

            fn per_leaf_score(&self) -> u64 {
                match self {
                    #(#score_arms)*
                    TapleafClass::Other(_) => 1,
                }
            }
        }
    }
}

fn emit_outer_score(top_level: &[ProcessedEntry]) -> TokenStream {
    let arms = top_level
        .iter()
        .map(|e| emit_score_arm(e, "DescriptorClass"));
    quote! {
        impl DescriptorClass {
            fn outer_score(&self) -> u64 {
                match self {
                    #(#arms)*
                    DescriptorClass::Other => 1,
                }
            }
        }
    }
}

/// One match arm of `per_leaf_score()` / `outer_score()`. Score equals the
/// number of patterns whose round-trip applies: non-musig patterns always do,
/// musig patterns require `threshold == len(keys)` (keys are guaranteed plain
/// by classification).
fn emit_score_arm(entry: &ProcessedEntry, class_enum: &str) -> TokenStream {
    let class = id(class_enum);
    let variant = id(&entry.name);
    let plain: u64 = entry
        .patterns
        .iter()
        .filter(|p| !pattern_uses_musig(p))
        .count() as u64;
    let musig: u64 = entry
        .patterns
        .iter()
        .filter(|p| pattern_uses_musig(p))
        .count() as u64;

    let destructure: TokenStream = if entry.fields.order.is_empty() {
        quote!()
    } else if musig > 0 {
        quote!({ threshold, keys, .. })
    } else {
        quote!({ .. })
    };

    let body: TokenStream = if musig == 0 {
        quote!(#plain)
    } else if musig == 1 {
        quote!(#plain + if *threshold as usize == keys.len() { 1 } else { 0 })
    } else {
        quote!(#plain + if *threshold as usize == keys.len() { #musig } else { 0 })
    };

    quote!(#class::#variant #destructure => #body,)
}

// ---------------------------------------------------------------------------
// from_cleartext_pattern (reverse: (PatternKind, Vec<CleartextValue>) -> class)
// ---------------------------------------------------------------------------

fn emit_from_cleartext_pattern(entries: &[ProcessedEntry], ck: ClassKind) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    let arms: Vec<TokenStream> = entries
        .iter()
        .map(|e| emit_from_cleartext_arm(e, ck))
        .collect();
    quote! {
        impl #class {
            fn from_cleartext_pattern(
                kind: #pattern,
                values: alloc::vec::Vec<CleartextValue>,
            ) -> Option<Self> {
                let mut __cur = CleartextValueCursor::new(values);
                let __res = match kind {
                    #(#arms)*
                };
                __cur.finish()?;
                __res
            }
        }
    }
}

fn emit_from_cleartext_arm(entry: &ProcessedEntry, ck: ClassKind) -> TokenStream {
    let class = ck.class();
    let pattern = ck.pattern();
    let variant = id(&entry.name);

    let mut popped: BTreeMap<String, ()> = BTreeMap::new();
    let pops: Vec<TokenStream> = entry
        .cleartext
        .iter()
        .filter_map(|t| match t {
            CleartextToken::Field { name, kind } => {
                let m = cursor_method(*kind);
                let n = id(name);
                popped.insert(name.clone(), ());
                Some(quote!(let #n = __cur.#m()?;))
            }
            _ => None,
        })
        .collect();

    let body = if entry.fields.order.is_empty() {
        quote!(Some(#class::#variant))
    } else {
        let fields = entry.fields.order.iter().map(|name| {
            let n = id(name);
            if popped.contains_key(name) {
                quote!(#n)
            } else {
                // The only field not in cleartext is `$leaves`; it's filled in
                // by the caller (`parse_top_level_candidates`) via Cartesian
                // product over per-leaf candidates, so initialize it empty.
                debug_assert_eq!(entry.fields.kinds[name], BindingKind::Leaves);
                quote!(#n: alloc::vec::Vec::new())
            }
        });
        quote!(Some(#class::#variant { #(#fields),* }))
    };

    quote! {
        #pattern::#variant => {
            #(#pops)*
            #body
        },
    }
}

// ---------------------------------------------------------------------------
// top_level_variants + tapleaf_to_descriptors (reverse construction)
// ---------------------------------------------------------------------------

fn emit_top_level_variants(top_level: &[ProcessedEntry]) -> TokenStream {
    let arms: Vec<TokenStream> = top_level.iter().map(emit_top_level_variants_arm).collect();
    quote! {
        fn top_level_variants(
            class: DescriptorClass,
        ) -> Result<alloc::boxed::Box<dyn Iterator<Item = DescriptorTemplate>>, CleartextDecodeError>
        {
            match class {
                #(#arms)*
                DescriptorClass::Other => Err(CleartextDecodeError::UnrecognizedPattern),
            }
        }
    }
}

fn emit_top_level_variants_arm(entry: &ProcessedEntry) -> TokenStream {
    let variant = id(&entry.name);

    // Destructure only fields the body references. For recursing entries we
    // always need `leaves`; non-musig recursing entries also need `internal_key`;
    // musig recursing entries need `keys`. Non-recursing entries reference all
    // fields by name (small classes; each name is used in at least one pattern).
    let destructure: TokenStream = if entry.fields.order.is_empty() {
        quote!()
    } else if entry.recurses {
        let key_field = if entry.fields.kinds.contains_key("internal_key") {
            id("internal_key")
        } else {
            id("keys")
        };
        let leaves = id("leaves");
        quote!({ #leaves, #key_field, .. })
    } else {
        let used: Vec<Ident> = entry.fields.order.iter().map(|s| id(s)).collect();
        quote!({ #(#used),* })
    };

    let body: TokenStream = if entry.recurses {
        let key_local = emit_internal_key_local(entry);
        quote! {
            let mut __per_leaf_variants: alloc::vec::Vec<alloc::vec::Vec<DescriptorTemplate>> =
                alloc::vec::Vec::new();
            for __leaf in &leaves {
                __per_leaf_variants.push(tapleaf_to_descriptors(__leaf)?);
            }
            #key_local
            if leaves.is_empty() {
                return Ok(alloc::boxed::Box::new(core::iter::once(
                    DescriptorTemplate::Tr(__internal_key, None),
                )));
            }
            let __trees = enumerate_taptrees(__per_leaf_variants);
            Ok(alloc::boxed::Box::new(__trees.map(move |__t| {
                let mut __dt = DescriptorTemplate::Tr(__internal_key.clone(), Some(__t));
                canonicalize_derivations(&mut __dt);
                __dt
            })))
        }
    } else {
        let block = emit_pattern_construction_block(entry, /*owned=*/ true);
        quote! {
            #block
            Ok(alloc::boxed::Box::new(__out.into_iter()))
        }
    };

    quote! {
        DescriptorClass::#variant #destructure => { #body },
    }
}

fn emit_tapleaf_to_descriptors(tapleaf: &[ProcessedEntry]) -> TokenStream {
    let arms: Vec<TokenStream> = tapleaf
        .iter()
        .map(|e| {
            let variant = id(&e.name);
            let destructure: TokenStream = if e.fields.order.is_empty() {
                quote!()
            } else {
                let fields: Vec<Ident> = e.fields.order.iter().map(|s| id(s)).collect();
                quote!({ #(#fields),* })
            };
            let block = emit_pattern_construction_block(e, /*owned=*/ false);
            quote! {
                TapleafClass::#variant #destructure => {
                    #block
                    Ok(__out)
                },
            }
        })
        .collect();
    quote! {
        fn tapleaf_to_descriptors(
            leaf: &TapleafClass,
        ) -> Result<alloc::vec::Vec<DescriptorTemplate>, CleartextDecodeError> {
            match leaf {
                #(#arms)*
                TapleafClass::Other(__s) => {
                    let dt = <DescriptorTemplate as core::str::FromStr>::from_str(__s)
                        .map_err(|e| {
                            CleartextDecodeError::InvalidDescriptor(alloc::format!("{:?}", e))
                        })?;
                    Ok(alloc::vec![dt])
                },
            }
        }
    }
}

/// Materialize `__internal_key` for a recursing entry. Taproot has the field
/// `internal_key` directly; TaprootMusig reconstructs it from `(threshold, keys)`.
fn emit_internal_key_local(entry: &ProcessedEntry) -> TokenStream {
    if entry.fields.kinds.contains_key("internal_key") {
        quote!(let __internal_key = internal_key;)
    } else {
        debug_assert!(entry.fields.kinds.contains_key("keys"));
        quote! {
            let __key_indices: alloc::vec::Vec<u32> = keys
                .iter()
                .map(|__k| __k.plain_key_index().expect("plain key"))
                .collect();
            let __num1 = keys.first().map(|__k| __k.num1).unwrap_or(0);
            let __num2 = keys.first().map(|__k| __k.num2).unwrap_or(1);
            let __internal_key = KeyExpression::musig(__key_indices, __num1, __num2);
        }
    }
}

/// Body of a non-recursing arm: build a `__out: Vec<DescriptorTemplate>` with
/// one entry per applicable pattern. `owned` controls whether numeric fields
/// are bound by value (`u32`) or by reference (`&u32`).
fn emit_pattern_construction_block(entry: &ProcessedEntry, owned: bool) -> TokenStream {
    let pushes = entry.patterns.iter().map(|pat| {
        let expr = build_construction_expr(pat, owned);
        if pattern_uses_musig(pat) {
            let t: TokenStream = if owned {
                quote!(threshold)
            } else {
                quote!(*threshold)
            };
            quote! {
                if #t as usize == keys.len() && keys.iter().all(|__k| __k.is_plain()) {
                    __out.push(#expr);
                }
            }
        } else {
            quote!(__out.push(#expr);)
        }
    });
    quote! {
        let mut __out: alloc::vec::Vec<DescriptorTemplate> = alloc::vec::Vec::new();
        #(#pushes)*
    }
}

fn build_construction_expr(pat: &Pattern, owned: bool) -> TokenStream {
    let variant_str = keyword_to_variant(&pat.keyword).expect("keyword validated");
    let variant = id(variant_str);
    let arg_kinds = variant_arg_kinds(variant_str);
    if pat.args.is_empty() {
        return quote!(DescriptorTemplate::#variant);
    }
    let args =
        pat.args.iter().enumerate().map(|(i, a)| {
            build_arg_expr(a, arg_kinds.get(i).copied().unwrap_or(ArgKind::Sub), owned)
        });
    quote!(DescriptorTemplate::#variant(#(#args),*))
}

fn build_arg_expr(arg: &PatternArg, kind: ArgKind, owned: bool) -> TokenStream {
    match arg {
        PatternArg::Binding { name, .. } => {
            let n = id(name);
            match kind {
                ArgKind::Key | ArgKind::KeyList => quote!(#n.clone()),
                ArgKind::Num => {
                    if owned {
                        quote!(#n)
                    } else {
                        quote!(*#n)
                    }
                }
                ArgKind::Sub => quote!(#n),
                ArgKind::Tree => quote!(None),
            }
        }
        PatternArg::Musig { keys, .. } => {
            let k = id(keys);
            quote! {
                KeyExpression::musig(
                    #k.iter().map(|__k| __k.plain_key_index().expect("plain key")).collect(),
                    #k.first().map(|__k| __k.num1).unwrap_or(0),
                    #k.first().map(|__k| __k.num2).unwrap_or(1),
                )
            }
        }
        PatternArg::Sub { wrappers, inner } => {
            let mut expr = build_construction_expr(inner, owned);
            for w in wrappers.iter().rev() {
                let wv = id(w);
                expr = quote!(DescriptorTemplate::#wv(alloc::boxed::Box::new(#expr)));
            }
            match kind {
                ArgKind::Sub => quote!(alloc::boxed::Box::new(#expr)),
                _ => expr,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level emit: assemble the file and pretty-print
// ---------------------------------------------------------------------------

/// Render a `TokenStream` to a pretty-printed Rust source string with a leading
/// "do not edit" banner.
fn pretty_file(file: TokenStream) -> String {
    let parsed = syn::parse_file(&file.to_string()).expect("generated code is valid Rust");
    let body = prettyplease::unparse(&parsed);
    format!(
        "// AUTO-GENERATED by build.rs from src/cleartext/specs/cleartext.toml. Do not edit.\n\
         // To regenerate: edit the spec and rebuild.\n\n{body}"
    )
}

/// Code that is part of every build: class/pattern enums, spec tables, forward
/// classification, encode-side `cleartext_pattern`, and the score helpers used
/// by `confusion_score`.
fn emit_common(top_level: &[ProcessedEntry], tapleaf: &[ProcessedEntry]) -> String {
    let pat_kind_top = emit_pattern_kind_enum("TopLevelPattern", top_level);
    let pat_kind_tap = emit_pattern_kind_enum("TapleafPattern", tapleaf);
    let class_top = emit_class_enum(TOP_LEVEL, top_level);
    let class_tap = emit_class_enum(TAPLEAF, tapleaf);
    let specs_top = emit_specs_const("TOP_LEVEL_SPECS", TOP_LEVEL, top_level);
    let specs_tap = emit_specs_const("TAPLEAF_SPECS", TAPLEAF, tapleaf);
    let classify_top = emit_classify(top_level, TOP_LEVEL, "classify");
    let classify_tap = emit_classify(tapleaf, TAPLEAF, "classify_as_tapleaf");
    let cleartext_top = emit_cleartext_pattern(top_level, TOP_LEVEL);
    let cleartext_tap = emit_cleartext_pattern(tapleaf, TAPLEAF);
    let tap_helpers = emit_tapleaf_helpers(tapleaf);
    let outer = emit_outer_score(top_level);

    pretty_file(quote! {
        #pat_kind_top
        #pat_kind_tap
        #class_top
        #class_tap
        #specs_top
        #specs_tap

        impl DescriptorTemplate {
            #classify_top
            #classify_tap
        }

        #cleartext_top
        #cleartext_tap
        #tap_helpers
        #outer
    })
}

/// Code only needed when reverse-parsing cleartext (the `cleartext-decode`
/// feature, or `cfg(test)`): `from_cleartext_pattern` for both class enums,
/// plus `top_level_variants` and `tapleaf_to_descriptors`. This file is
/// included from a feature-gated submodule, so no `#[cfg]` attributes are
/// emitted here.
fn emit_decode(top_level: &[ProcessedEntry], tapleaf: &[ProcessedEntry]) -> String {
    let from_top = emit_from_cleartext_pattern(top_level, TOP_LEVEL);
    let from_tap = emit_from_cleartext_pattern(tapleaf, TAPLEAF);
    let top_variants = emit_top_level_variants(top_level);
    let tap_to_desc = emit_tapleaf_to_descriptors(tapleaf);

    pretty_file(quote! {
        #from_top
        #from_tap
        #top_variants
        #tap_to_desc
    })
}

// ---------------------------------------------------------------------------
// main()
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")?;
    let spec_path = PathBuf::from(&manifest_dir).join("src/cleartext/specs/cleartext.toml");
    println!("cargo:rerun-if-changed={}", spec_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    let raw = fs::read_to_string(&spec_path)?;
    let spec: Spec = toml::from_str(&raw)?;

    let top_level = process_entries(&spec.top_level).map_err(|e| format!("top_level: {}", e))?;
    let tapleaf = process_entries(&spec.tapleaf).map_err(|e| format!("tapleaf: {}", e))?;

    check_cleartext_uniqueness(&top_level, "top_level")?;
    check_cleartext_uniqueness(&tapleaf, "tapleaf")?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        out_dir.join("cleartext_generated.rs"),
        emit_common(&top_level, &tapleaf),
    )?;
    fs::write(
        out_dir.join("cleartext_decode_generated.rs"),
        emit_decode(&top_level, &tapleaf),
    )?;
    Ok(())
}
