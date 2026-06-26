# `bip388`

A `no_std`, allocator-backed Rust crate for parsing, serializing and
**clear-signing** [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki)
wallet policies.

The crate has two concerns:

1. **Wallet policies.** Parse a BIP-388 descriptor template into a typed AST,
   validate it, serialize/deserialize it, and re-derive concrete descriptors for
   a given `(is_change, address_index)`.
2. **Cleartext display**. Turn a descriptor template into a short, human-readable
   description of *who can spend and how*, so a hardware signer can show a wallet
   policy in plain language instead of an opaque descriptor string - but only when
   the safety of doing so can be measured.

---

## Table of contents

- [Background: BIP-388 wallet policies](#background-bip-388-wallet-policies)
- [Crate structure](#crate-structure)
- [Core API: descriptor templates and wallet policies](#core-api-descriptor-templates-and-wallet-policies)
  - [`DescriptorTemplate`](#descriptortemplate)
  - [`WalletPolicy`](#walletpolicy)
  - [Serialization format](#serialization-format)
  - [Safety limits](#safety-limits)
- [The cleartext feature](#the-cleartext-feature)
  - [Goals and security properties](#goals-and-security-properties)
  - [Architecture](#architecture)
  - [The spec file as a single source of truth](#the-spec-file-as-a-single-source-of-truth)
  - [Designed for multiple language implementations](#designed-for-multiple-language-implementations)
  - [The confusion score](#the-confusion-score)
  - [Wording conventions](#wording-conventions)
  - [The `cleartext-decode` feature](#the-cleartext-decode-feature)
- [Cargo features](#cargo-features)
- [Testing](#testing)

---

## Background: BIP-388 wallet policies

A **wallet policy**, defined in [BIP-388](https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki), is similar to a [descriptor](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) but split into two parts:

- a **descriptor template**, where every key is replaced by a placeholder
  `@i` that points into...
- a **key information vector**, the ordered list of the actual extended keys
  (`[origin]xpub`) the placeholders refer to.

For example the policy

```text
template:  wsh(sortedmulti(2,@0/**,@1/**))
keys:      @0 = [f5acc2fd/48'/1'/0'/2']tpub.../...
           @1 = [...]tpub.../...
```

describes a 2-of-2 segwit multisig. The `/**` suffix is BIP-388 shorthand for
the `<0;1>/*` receive/change derivation; a key can also use an explicit
`/<num1;num2>/*` form. This split lets a single template stand for an entire
account (all addresses, receive and change) and makes templates comparable
independently of the concrete keys.

This crate implements parsing, validation and serialization of templates and
policies, plus the cleartext rendering described below.

## Crate structure

```text
bip388/
├── build.rs                         # spec → Rust code generator (see below)
├── src/
│   ├── lib.rs                       # descriptor template AST, parser, WalletPolicy
│   ├── time.rs                      # timelock formatting/parsing (durations, UTC dates)
│   └── cleartext/
│       ├── mod.rs                   # encoder, confusion score, canonical ordering
│       ├── decode.rs                # reverse parser  (feature: cleartext-decode)
│       └── specs/
│           ├── cleartext.toml       # the single source of truth for cleartext
│           └── test_vectors.toml    # encode/decode/score test vectors
```

The notable architectural choice is that the cleartext behaviour is **not**
hand-written: it is *generated at build time* from a declarative specification
file, [`src/cleartext/specs/cleartext.toml`](src/cleartext/specs/cleartext.toml).
[`build.rs`](build.rs) parses that file and emits the classifier, the encoder
tables, the scoring helpers and (optionally) the reverse parser. See
[The spec file as a single source of truth](#the-spec-file-as-a-single-source-of-truth).

## Core API: descriptor templates and wallet policies

### `DescriptorTemplate`

[`DescriptorTemplate`](src/lib.rs) is the typed AST of a parsed template. It
covers the descriptor fragments relevant to wallet policies - the top-level
forms (`pkh`, `wpkh`, `sh`, `wsh`, `tr`, `multi`/`sortedmulti`,
`multi_a`/`sortedmulti_a`), the miniscript fragments and wrappers, and the
`musig(...)` key form from
[BIP-390](https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki).

```rust
use core::str::FromStr;
use bip388::DescriptorTemplate;

let t = DescriptorTemplate::from_str("wsh(sortedmulti(2,@0/**,@1/**))")?;
```

Parsing is **context-aware**: a `ParseContext` tracks which top-level descriptor
the parser is inside, so script-form rules are enforced (e.g. `sh` only at the
top level, `wpkh`/`wsh` only at the top level or inside `sh`, `musig` only inside
`tr`). Numbers reject illegal leading zeros and out-of-range values; recursion
depth is bounded. Errors are reported through the [`ParseError`](src/lib.rs)
enum.

Useful operations on a template:

- `Display` - re-serialize the template back to its canonical string.
- `placeholders()` / `placeholders_mut()` - iterate the key placeholders in a
  fixed traversal order (used by the cleartext machinery).
- `classify()` - map the template onto a recognized spending-policy shape
  (internal to the cleartext module).
- the [`ClearText`](src/cleartext/mod.rs) trait - `to_cleartext()`,
  `confusion_score()`, and (feature-gated) `from_cleartext()`.

### `WalletPolicy`

[`WalletPolicy`](src/lib.rs) bundles a parsed template with its
`Vec<KeyInformation>` and the **exact original template string**:

```rust
use bip388::{WalletPolicy, KeyInformation};

let policy = WalletPolicy::new("wsh(sortedmulti(2,@0/**,@1/**))", key_info)?;
```

A `WalletPolicy` is **immutable** once constructed, and its fields are private.
This is deliberate: the raw template string is what gets HMAC'd during account
registration, so it is preserved byte-for-byte (`descriptor_template_raw()`)
rather than re-derived through `Display`, ensuring the parsed AST can never drift
from the bytes that were authenticated.

The [`ToDescriptor`](src/lib.rs) trait turns a template (with its key info) into
a concrete, fully-derived descriptor for a specific address:

```rust
let descriptor = policy.descriptor_template()
    .to_descriptor(policy.key_information(), /*is_change=*/ false, /*address_index=*/ 0)?;
```

`get_segwit_version()` reports whether the policy is Legacy, SegWit v0 or
Taproot.

### Serialization format

`WalletPolicy::serialize` / `deserialize` use a compact binary encoding (Bitcoin
`VarInt` lengths, big-endian fingerprints, little-endian derivation steps,
78-byte serialized xpubs):

```text
varint  len(template_string)
bytes   template_string
varint  num_keys
repeat num_keys:
    u8      origin flag (0 = none, 1 = present)
    if 1:
        be32    fingerprint
        varint  derivation_path_len
        le32 *  derivation steps
    78 bytes  serialized xpub
```

This is the same serialization format used in the [Ledger Bitcoin app](https://github.com/LedgerHQ/app-bitcoin-new).

`deserialize` is hardened against hostile input: every length is bounds-checked
*before* allocation, and trailing bytes after a complete policy are rejected.

### Safety limits

The parser and deserializer enforce explicit bounds to limit the maximum resource usage:

| limit | value | what it bounds |
|-------|-------|----------------|
| `MAX_KEYS_MULTI` | 20 | keys in `multi`/`sortedmulti` (consensus limit) |
| `MAX_KEYS_MULTI_A` | 999 | keys in `multi_a`/`sortedmulti_a` |
| `MAX_PARSE_DEPTH` | 64 | descriptor / tap-tree nesting depth |
| `MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN` | 4096 | serialized template byte length |
| `MAX_SERIALIZED_KEY_COUNT` | 999 | key-information entries on deserialize |
| `MAX_BIP32_DERIVATION_PATH_LEN` | 32 | origin derivation path length |

---

## The cleartext feature

The cleartext feature converts a descriptor template into one or more short
English sentences describing the spending policy. It lives in
[`src/cleartext/`](src/cleartext/) and is always compiled (the reverse direction
is the only feature-gated part).

A few examples (`@i` placeholders are shown as-is; a UI substitutes key labels):

| template | cleartext |
|----------|-----------|
| `pkh(@0/**)` | `Spendable by @0 alone (Legacy)` |
| `wpkh(@0/**)` | `Spendable by @0 alone (SegWit)` |
| `tr(@0/**)` | `Spendable by @0 alone (Taproot)` |
| `wsh(sortedmulti(2,@0/**,@1/**))` | `Each of @0 and @1 must sign` |
| `wsh(sortedmulti(2,@0/**,@1/**,@2/**))` | `Any 2 of @0, @1 and @2 must sign` |
| `tr(musig(@0,@1)/**)` | `Each of @0 and @1 must sign` |

Taproot descriptors with a script tree produce **one line per spending path** -
the key path first, then one line per leaf, in a canonical order:

```text
template:  tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})

cleartext: Main path: spendable by @0
           @1 must sign
           @2 must sign
           @3 must sign
```

The leaves are **alternative** spending paths (any one suffices); conditions
*within* a leaf are combined with AND (rendered as "... must both sign" or
" - and also - "). Timelocks read e.g. "... , 144 blocks after receiving" or
"... , not before 2024-01-01 UTC".

### Goals and security properties

The cleartext machinery exists to improve clear-signing without ever misleading
the user. Its design centres on a few properties:

1. **Never claim a wrong policy.** A descriptor should be shown in cleartext only
   when the rendering is provably unambiguous enough - see
   [the confusion score](#the-confusion-score). When in doubt, the caller falls
   back to displaying the raw descriptor template.

2. **Limited information loss.** The cleartext omits per-key derivation suffixes
   (`/**`, `/<num1;num2>/*`). It is only allowed to do so when those derivations
   are *canonical* - for each key, its occurrences carry exactly the standard
   pairs `<0;1>`, `<2;3>`, ..., in some order. If they don't, the descriptor is not
   summarized at all. The only remaining freedom (which pair is assigned to which
   occurrence) is accounted for in the confusion score.

3. **Encoder/decoder consistency by construction.** Both directions are driven
   by the *same* declarative spec, so the human-readable forms and the set of
   descriptors that map to them cannot drift apart. The reverse parser
   (`from_cleartext`) is used in tests to round-trip every encoder output back
   to a set of candidate templates and check the original is among them.

4. **Determinism.** The output of `to_cleartext` for a given policy is fully
   deterministic. In particular taproot leaves are emitted in a canonical order
   (`TapleafClass::display_cmp`) independent of how the tap-tree was written, so
   the same policy always reads the same way.

5. **Safe on a constrained VM.** `no_std`, bounded allocations, and no panics on
   adversarial input: spec/classifier mismatches degrade to showing the raw
   descriptor (guarded by `debug_assert!` in debug builds) rather than aborting.

6. **Lightweight encoding.** The cleartext encoding machinery is kept as
   lightweight as possible, in order to be easy to reimplement in other languages,
   or constrained embedded devices. The decoding is substantially more complex
   (both in terms of code and possible running times), and it's only intended as
   a recovery tool.

### Architecture

The encoder pipeline (in [`src/cleartext/mod.rs`](src/cleartext/mod.rs)) has five
stages:

1. **Classification.** `DescriptorTemplate::classify` /
   `classify_as_tapleaf` map the full AST onto a small set of recognized
   spending-policy shapes (`DescriptorClass` / `TapleafClass`). Anything
   unrecognized becomes `Other`.

2. **Spec-driven formatting.** Each recognized shape has a `CleartextSpec`: an
   array of `CleartextPart` tokens (literal strings interleaved with typed
   dynamic fields - key indices, thresholds, lock values, recursive
   sub-policies). `to_cleartext` walks the spec and fills in the fields.

3. **Confusion score.** A single cleartext can correspond to several distinct
   templates. `confusion_score()` quantifies that ambiguity; the caller only
   shows cleartext when it is `<= MAX_CONFUSION_SCORE`.

4. **Canonical display order.** Taproot leaves are sorted with
   `TapleafClass::display_cmp` so output is independent of the original tree
   shape. The number of distinct trees that fold to the same ordering is folded
   into the confusion score.

5. **Reverse parsing** (feature-gated). `from_cleartext` parses a cleartext
   description back into *all* structurally distinct candidate templates,
   including enumeration of taproot tree topologies. See
   [`cleartext-decode`](#the-cleartext-decode-feature).

### The spec file as a single source of truth

Everything about how a shape is recognized, rendered, scored and (reverse-)parsed
is declared in [`specs/cleartext.toml`](src/cleartext/specs/cleartext.toml).
There are two tables - `[[top_level]]` (matched against the root template) and
`[[tapleaf]]` (matched against each leaf of a `tr(...)` tree) - sharing one
schema:

```toml
[[top_level]]
name = "Multisig"                     # variant name in the generated class enum
patterns = [                          # descriptor shapes that map to this class...
    "wsh(multi($threshold, $keys))",
    "wsh(sortedmulti($threshold, $keys))",
    "tr(musig($keys))",
    # ...several more on-chain encodings...
]
cleartext = ["Any ", "$threshold", " of ", "$keys", " must sign"]
cleartext_all = ["Each of ", "$keys", " must sign"]   # n-of-n wording
```

`$bindings` capture dynamic data; the binding *name* determines its type
(`$key`/`$internal_key` → a key, `$keys` → a key list, `$threshold` → a number,
`$timelock` → a relative/absolute lock, `$sub`/`$leaves` → recursive
sub-policies). A pattern can include miniscript wrappers (`v:`), `musig(...)`,
and nested fragments.

[`build.rs`](build.rs) compiles this file into Rust:

- `cleartext_generated.rs` (always compiled): the class/pattern enums, the
  `CleartextSpec` tables, the `classify*` and `cleartext_pattern` methods, and
  the scoring helpers.
- `cleartext_decode_generated.rs` (compiled with `cleartext-decode`): the
  reverse-construction functions.

Crucially, `build.rs` also **enforces, at build time, the invariants the runtime
parser depends on** - among them: every pattern parses fully; bindings shared
across an entry's patterns agree on type; cleartext literals are non-empty,
contain no `@`, and don't start/end with a digit (so numeric and key fields are
unambiguous next to a literal); no two dynamic fields are adjacent; and, within
each section, no two entries collapse to the same cleartext "shape". A spec edit
that would make decoding ambiguous fails the build with a clear message rather
than silently shipping an ambiguous renderer.

### Designed for multiple language implementations

Because the entire cleartext behaviour is *derived from a declarative spec plus a
handful of documented, deterministic algorithms*, the crate is structured to make
a faithful reimplementation in another language (e.g. for a different signer
firmware) tractable:

- **The spec is language-agnostic data.** `cleartext.toml` describes *what* the
  mapping is, not *how* a particular language implements it. The Rust code
  generator is one consumer; another language can consume the same file (or a
  port of it) to drive its own classifier/encoder.
- **Logic is separated from policy.** The security-relevant decisions live in
  the spec and in clearly delineated algorithms (the confusion score, the
  canonical leaf ordering, the timelock formatting, the derivation-canonicality
  check). None of these depend on Rust-specific behaviour, so they can be
  specified once and matched across implementations.
- **Round-trip test vectors are shared, not implementation-specific.**
  [`specs/test_vectors.toml`](src/cleartext/specs/test_vectors.toml) pins, for
  each template, its expected cleartext, `has_cleartext` flag and
  `confusion_score`. Any implementation in any language can be validated against
  the same vectors, which is what keeps independent implementations in agreement.
- **Minimal, explicit primitives.** Wording, number formatting and date/duration
  handling are localized in small functions ([`time.rs`](src/time.rs),
  `format_timelock`, `format_key*`) so they can be reproduced exactly.

The intent is that the cleartext rendering - the part a user trusts - has a
single canonical definition, with the test vectors as the contract that every
implementation must satisfy.

### The confusion score

`confusion_score()` returns an **upper bound on the number of distinct descriptor
templates that would render to the same cleartext**. It is the core safety knob:
a higher score means more policies look identical in plain language, so above
`MAX_CONFUSION_SCORE` (currently **100 000**) the caller must show the raw
descriptor instead.

The score is a product of independent sources of ambiguity:

```text
confusion_score =  outer_score
                ×  ∏ per_leaf_score(leaf)          (taproot only)
                ×  T(n)                              (taproot only; n = #leaves)
                ×  key_derivation_orderings_count
```

- **`outer_score` / `per_leaf_score`** - how many distinct *on-chain encodings*
  collapse to the same wording. This equals the number of the entry's patterns
  whose round-trip applies. For example the `Multisig` class coalesces seven
  encodings (`sh`/`wsh`/`sh(wsh)` over `multi`/`sortedmulti`, plus the leaf-less
  `tr(musig(...))` key-path), so a generic k-of-n multisig scores 7 if the
  musig form is admissible. A musig pattern only counts when it is genuinely
  n-of-n (`threshold == #keys`), since `musig` is inherently n-of-n; this is why
  a 2-of-3 scores 6 (no musig form) but a 3-of-3 scores 7.

- **`T(n)` - taproot tree shapes.** A cleartext lists the leaves in canonical
  order but says nothing about the *shape* of the tap-tree that holds them. The
  number of distinct unordered binary tree topologies on `n` leaves is the double
  factorial `T(n) = (2n − 3)!! = 1·3·5·...·(2n−3)` for `n > 1` (and `T(1) = 1`). So
  three leaves can be arranged in `T(3) = 3` shapes - which is exactly why
  `tr(@0/**,{{pk(@1/**),pk(@2/**)},pk(@3/**)})` scores 3.

- **`key_derivation_orderings_count`** - the cleartext drops derivation suffixes,
  so descriptors that differ only in which canonical pair (`<0;1>`, `<2;3>`, ...) is
  assigned to which occurrence of a key re-encode identically. If a key index
  occurs `k` times, those occurrences can be permuted `k!` ways; the count is the
  product of `k!` over all key indices. `musig(@i,@j,...)` groups are **expanded to
  their member indices** before counting.

This count is a deliberate **over-count**, and the module documents *why that is
the safe direction*. Over-counting can only ever overestimate the amount of work
necessary to track down the correct descriptor, given the corresponding cleartext.
Therefore, if the `MAX_CONFUSION_SCORE` is safe in the absence of over-counting,
the reverse parser may yield *fewer* candidates than the score, which is also safe.

### Wording conventions

The phrasing is chosen so that fragments compose correctly and decode
unambiguously (the rules are documented at the top of
[`cleartext.toml`](src/cleartext/specs/cleartext.toml)).

The tests of the crate enforce a number of invariants to make sure that this
property persists if the specs are updated.

### The `cleartext-decode` feature

The **reverse** direction - `ClearText::from_cleartext`, which parses cleartext
descriptions back into the set of candidate descriptor templates - lives in
[`src/cleartext/decode.rs`](src/cleartext/decode.rs) and is compiled only when
the `cleartext-decode` feature (or `cfg(test)`) is active:

```rust
#[cfg(any(test, feature = "cleartext-decode"))]
fn from_cleartext(descriptions: &[&str])
    -> Result<Box<dyn Iterator<Item = Self>>, CleartextDecodeError>;
```

It returns a lazy iterator over **all structurally distinct templates** that
would produce the given cleartext, enumerating taproot tree topologies along the
way (so the number of yielded instances corresponds to the confusion score, up to
its over-counting). Errors are reported via `CleartextDecodeError`.

This direction is intentionally **excluded from the default build**.
Decoding is needed off-device - for the crate's own round-trip tests, and for
host-side tooling to recover from a possibly lost descriptor template by enumerating
all the possible ones.

## Cargo features

| feature | default | effect |
|---------|---------|--------|
| `cleartext-decode` | off | Compiles the reverse parser (`from_cleartext`, `CleartextDecodeError`) and the `cleartext_decode_generated.rs` codegen. |

The crate is `#![no_std]` (with `extern crate alloc`) except under `cfg(test)`.

## Testing

All tests live in `#[cfg(test)]` modules inside the crate, so the full suite runs
with:

```sh
cargo test
```

The reverse parser is compiled under `cfg(test)` as well as under the
`cleartext-decode` feature, so `cargo test` automatically exercises the
round-trip tests (every encoder output is parsed back with `from_cleartext` and
the original template is checked to be among the candidates) without any extra
flags.

Much of the coverage is data-driven: the vectors in
[`specs/test_vectors.toml`](src/cleartext/specs/test_vectors.toml) pin, for each
template, its expected cleartext, `has_cleartext` flag and `confusion_score`, and
the tests assert the implementation matches them. Adding a case to that file is
usually all that's needed to cover a new shape.

To build and test with the reverse parser exposed as a public API (rather than
only under `cfg(test)`):

```sh
cargo test --features cleartext-decode
```

Note that several spec invariants are enforced at build time by
[`build.rs`](build.rs) (see [the spec file section](#the-spec-file-as-a-single-source-of-truth)),
so an ambiguous or malformed spec edit fails `cargo build` before any test runs.
