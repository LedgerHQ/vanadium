// TODO:
// - add type checks
// - add malleability checks
// - add stack limits and other safety checks

mod cleartext;
mod time;

pub use cleartext::*;

use alloc::{boxed::Box, string::String, vec, vec::Vec};

#[cfg(test)]
use alloc::{format, string::ToString};

use core::str::FromStr;

use hex::{self, FromHex};

use bitcoin::{
    bip32::{ChildNumber, Xpub},
    consensus::{encode, Decodable, Encodable},
    io::Read,
    VarInt,
};

const HARDENED_INDEX: u32 = 0x80000000u32;
const MAX_OLDER_AFTER: u32 = 2147483647; // maximum allowed in older/after

/// Error type for descriptor template / wallet policy parsing and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Input string was empty when content was expected.
    EmptyInput,
    /// Parsing succeeded but left unconsumed input.
    TrailingInput,
    /// A required syntactic token was missing or unexpected.
    InvalidSyntax,
    /// Hex-encoded data was not valid hex.
    InvalidHex,
    /// A key, xpub, fingerprint, hash, or compressed-key byte was invalid.
    InvalidKey,
    /// A numeric literal was out of range or had illegal leading zeros.
    NumberOutOfRange,
    /// A data field was the wrong length.
    InvalidLength,
    /// An unrecognized descriptor fragment keyword was encountered.
    UnrecognizedFragment,
    /// A multisig/sortedmulti fragment had fewer than 2 key placeholders.
    TooFewKeyPlaceholders,
    /// The threshold `k` in `thresh(k, ...)` exceeds the number of sub-scripts.
    ThreshExceedsScripts,
    /// A key placeholder index was out of range for the key-information list.
    InvalidKeyIndex,
    /// The top-level descriptor type is not supported.
    InvalidTopLevelPolicy,
    /// Writing a descriptor to a `String` buffer failed.
    FormatError,
    /// `sh`/`wsh`/`wpkh` used in a position that is not allowed by the spec.
    InvalidScriptContext,
    /// Too many keys for a multisig fragment.
    TooManyKeys,
    /// Invalid multisig quorum (threshold).
    InvalidMultisigQuorum,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<ChildNumber>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyInformation {
    pub pubkey: Xpub,
    pub origin_info: Option<KeyOrigin>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct KeyPlaceholder {
    pub key_index: u32,
    pub num1: u32,
    pub num2: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum DescriptorTemplate {
    Sh(Box<DescriptorTemplate>),
    Wsh(Box<DescriptorTemplate>),
    Pkh(KeyPlaceholder),
    Wpkh(KeyPlaceholder),
    Sortedmulti(u32, Vec<KeyPlaceholder>),
    Sortedmulti_a(u32, Vec<KeyPlaceholder>),
    Tr(KeyPlaceholder, Option<TapTree>),

    Zero,
    One,
    Pk(KeyPlaceholder),
    Pk_k(KeyPlaceholder),
    Pk_h(KeyPlaceholder),
    Older(u32),
    After(u32),
    Sha256([u8; 32]),
    Ripemd160([u8; 20]),
    Hash256([u8; 32]),
    Hash160([u8; 20]),
    Andor(
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
        Box<DescriptorTemplate>,
    ),
    And_v(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    And_n(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_b(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_c(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_d(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Or_i(Box<DescriptorTemplate>, Box<DescriptorTemplate>),
    Thresh(u32, Vec<DescriptorTemplate>),
    Multi(u32, Vec<KeyPlaceholder>),
    Multi_a(u32, Vec<KeyPlaceholder>),

    // wrappers
    A(Box<DescriptorTemplate>),
    S(Box<DescriptorTemplate>),
    C(Box<DescriptorTemplate>),
    T(Box<DescriptorTemplate>),
    D(Box<DescriptorTemplate>),
    V(Box<DescriptorTemplate>),
    J(Box<DescriptorTemplate>),
    N(Box<DescriptorTemplate>),
    L(Box<DescriptorTemplate>),
    U(Box<DescriptorTemplate>),
}

pub struct DescriptorTemplateIter<'a> {
    fragments: Vec<(&'a DescriptorTemplate, Option<&'a DescriptorTemplate>)>, // Store DescriptorTemplate and its associated leaf context
    placeholders: Vec<(&'a KeyPlaceholder, Option<&'a DescriptorTemplate>)>, // Placeholders also carry the leaf context
}

impl<'a> From<&'a DescriptorTemplate> for DescriptorTemplateIter<'a> {
    fn from(desc: &'a DescriptorTemplate) -> Self {
        DescriptorTemplateIter {
            fragments: vec![(desc, None)], // Initially, there is no associated leaf context
            placeholders: Vec::new(),
        }
    }
}

impl<'a> Iterator for DescriptorTemplateIter<'a> {
    type Item = (&'a KeyPlaceholder, Option<&'a DescriptorTemplate>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.placeholders.len() > 0 || self.fragments.len() > 0 {
            // If there are pending placeholders, pop and return one
            if let Some(item) = self.placeholders.pop() {
                return Some(item);
            }

            let next_fragment = self.fragments.pop();
            if next_fragment.is_none() {
                break;
            }
            let (frag, tapleaf_desc) = next_fragment.unwrap();
            match frag {
                DescriptorTemplate::Sh(sub)
                | DescriptorTemplate::Wsh(sub)
                | DescriptorTemplate::A(sub)
                | DescriptorTemplate::S(sub)
                | DescriptorTemplate::C(sub)
                | DescriptorTemplate::T(sub)
                | DescriptorTemplate::D(sub)
                | DescriptorTemplate::V(sub)
                | DescriptorTemplate::J(sub)
                | DescriptorTemplate::N(sub)
                | DescriptorTemplate::L(sub)
                | DescriptorTemplate::U(sub) => {
                    self.fragments.push((sub, tapleaf_desc));
                }

                DescriptorTemplate::Andor(sub1, sub2, sub3) => {
                    self.fragments.push((sub3, tapleaf_desc));
                    self.fragments.push((sub2, tapleaf_desc));
                    self.fragments.push((sub1, tapleaf_desc));
                }

                DescriptorTemplate::Or_b(sub1, sub2)
                | DescriptorTemplate::Or_c(sub1, sub2)
                | DescriptorTemplate::Or_d(sub1, sub2)
                | DescriptorTemplate::Or_i(sub1, sub2)
                | DescriptorTemplate::And_v(sub1, sub2)
                | DescriptorTemplate::And_b(sub1, sub2)
                | DescriptorTemplate::And_n(sub1, sub2) => {
                    self.fragments.push((sub2, tapleaf_desc));
                    self.fragments.push((sub1, tapleaf_desc));
                }

                DescriptorTemplate::Tr(key, tree) => {
                    self.placeholders.push((key, None));
                    if let Some(t) = tree {
                        let mut leaves: Vec<_> = t.tapleaves().collect();
                        leaves.reverse();
                        for leaf in leaves {
                            self.fragments.push((leaf, Some(leaf)));
                        }
                    }
                }

                DescriptorTemplate::Pkh(key)
                | DescriptorTemplate::Wpkh(key)
                | DescriptorTemplate::Pk(key)
                | DescriptorTemplate::Pk_k(key)
                | DescriptorTemplate::Pk_h(key) => {
                    return Some((key, tapleaf_desc));
                }

                DescriptorTemplate::Sortedmulti(_, keys)
                | DescriptorTemplate::Sortedmulti_a(_, keys)
                | DescriptorTemplate::Multi(_, keys)
                | DescriptorTemplate::Multi_a(_, keys) => {
                    // Push keys onto the keys stack in reverse order
                    for key in keys.iter().rev() {
                        self.placeholders.push((key, tapleaf_desc));
                    }
                }

                DescriptorTemplate::Thresh(_, descs) => {
                    for desc in descs.iter().rev() {
                        self.fragments.push((desc, tapleaf_desc));
                    }
                }

                DescriptorTemplate::Zero
                | DescriptorTemplate::One
                | DescriptorTemplate::Older(_)
                | DescriptorTemplate::After(_)
                | DescriptorTemplate::Sha256(_)
                | DescriptorTemplate::Ripemd160(_)
                | DescriptorTemplate::Hash256(_)
                | DescriptorTemplate::Hash160(_) => {
                    // nothing to do, there are no placeholders for these
                }
            }
        }

        None
    }
}

impl DescriptorTemplate {
    /// Determines if root fragment is a wrapper.
    fn is_wrapper(&self) -> bool {
        match &self {
            DescriptorTemplate::A(_) => true,
            DescriptorTemplate::S(_) => true,
            DescriptorTemplate::C(_) => true,
            DescriptorTemplate::T(_) => true,
            DescriptorTemplate::D(_) => true,
            DescriptorTemplate::V(_) => true,
            DescriptorTemplate::J(_) => true,
            DescriptorTemplate::N(_) => true,
            DescriptorTemplate::L(_) => true,
            DescriptorTemplate::U(_) => true,
            _ => false,
        }
    }
    pub fn placeholders(&self) -> DescriptorTemplateIter<'_> {
        DescriptorTemplateIter::from(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TapTree {
    Script(Box<DescriptorTemplate>),
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    pub fn tapleaves(&self) -> TapleavesIter<'_> {
        TapleavesIter::new(self)
    }
}

pub struct TapleavesIter<'a> {
    stack: Vec<&'a TapTree>,
}

impl<'a> TapleavesIter<'a> {
    fn new(root: &'a TapTree) -> Self {
        TapleavesIter { stack: vec![root] }
    }
}

impl<'a> Iterator for TapleavesIter<'a> {
    type Item = &'a DescriptorTemplate;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(node) = self.stack.pop() {
            match node {
                TapTree::Script(descriptor) => return Some(descriptor),
                TapTree::Branch(left, right) => {
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
        None
    }
}

impl core::fmt::Display for TapTree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TapTree::Script(desc) => write!(f, "{}", desc),
            TapTree::Branch(left, right) => write!(f, "{{{},{}}}", left, right),
        }
    }
}

impl core::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.fingerprint)?;
        for step in &self.derivation_path {
            write!(f, "/{}", step)?;
        }
        Ok(())
    }
}

impl core::convert::TryFrom<&str> for KeyOrigin {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // parse a string in the form "76223a6e/48'/1'/0'/1'"
        // the key origin info between [] is optional and might not be present
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let parts: Vec<&str> = s.split('/').collect();
        if parts[0].len() != 8 {
            return Err(ParseError::InvalidLength);
        }
        let fingerprint = u32::from_str_radix(parts[0], 16).map_err(|_| ParseError::InvalidKey)?;
        let derivation_path = parts[1..]
            .iter()
            .map(|x| ChildNumber::from_str(x).map_err(|_| ParseError::InvalidKey))
            .collect::<Result<Vec<ChildNumber>, Self::Error>>()?;
        Ok(KeyOrigin {
            fingerprint,
            derivation_path,
        })
    }
}

impl core::fmt::Display for KeyInformation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.origin_info {
            Some(origin_info) => write!(f, "[{}]{}", origin_info, self.pubkey),
            None => write!(f, "{}", self.pubkey),
        }
    }
}

impl core::fmt::Display for KeyPlaceholder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.num1 == 0 && self.num2 == 1 {
            write!(f, "@{}/**", self.key_index)
        } else {
            write!(f, "@{}/<{};{}>/*", self.key_index, self.num1, self.num2)
        }
    }
}

impl TryFrom<&str> for KeyInformation {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let (origin_info, pubkey_pos) = if s.starts_with('[') {
            let end = s.find(']').ok_or(ParseError::InvalidKey)?;
            (Some(KeyOrigin::try_from(&s[1..end])?), end + 1)
        } else {
            (None, 0)
        };
        let pubkey = Xpub::from_str(&s[pubkey_pos..]).map_err(|_| ParseError::InvalidKey)?;
        Ok(KeyInformation {
            pubkey,
            origin_info,
        })
    }
}

pub trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError>;
}

// Return type for all hand-rolled parser functions: (remaining_input, parsed_value)
type ParseResult<'a, T> = Result<(&'a str, T), ParseError>;

// Parses a decimal u32 (no leading zeros unless "0"), value <= max.
fn parse_number_up_to(input: &str, max: u32) -> ParseResult<'_, u32> {
    if input.is_empty() || !input.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(ParseError::InvalidSyntax);
    }
    // reject leading zeros on multi-digit numbers
    if input.starts_with('0') && input.len() > 1 && input.as_bytes()[1].is_ascii_digit() {
        return Err(ParseError::NumberOutOfRange);
    }
    let end = input
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(input.len());
    let num: u32 = input[..end]
        .parse()
        .map_err(|_| ParseError::NumberOutOfRange)?;
    if num > max {
        return Err(ParseError::NumberOutOfRange);
    }
    Ok((&input[end..], num))
}

// Entry-point: parse a complete descriptor template string.
fn parse_descriptor_template(input: &str) -> Result<DescriptorTemplate, ParseError> {
    let (rest, descriptor) = parse_descriptor(input)?;
    if rest.is_empty() {
        Ok(descriptor)
    } else {
        Err(ParseError::TrailingInput)
    }
}

// Parses a derivation-step number like "44" or "44'".
fn parse_derivation_step_number(input: &str) -> ParseResult<'_, u32> {
    let (rest, num) = parse_number_up_to(input, HARDENED_INDEX - 1)?;
    if rest.starts_with('\'') {
        Ok((&rest[1..], num + HARDENED_INDEX))
    } else {
        Ok((rest, num))
    }
}

// Parses a key placeholder: @N/** or @N/<num1;num2>/*
fn parse_key_placeholder(input: &str) -> ParseResult<'_, KeyPlaceholder> {
    if !input.starts_with('@') {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, key_index) = parse_number_up_to(&input[1..], u32::MAX)?;
    if !rest.starts_with('/') {
        return Err(ParseError::InvalidSyntax);
    }
    let rest = &rest[1..];

    let (rest, (num1, num2)) = if rest.starts_with("**") {
        (&rest[2..], (0u32, 1u32))
    } else if rest.starts_with('<') {
        let rest = &rest[1..];
        let (rest, num1) = parse_derivation_step_number(rest)?;
        if !rest.starts_with(';') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, num2) = parse_derivation_step_number(&rest[1..])?;
        if !rest.starts_with(">/*") {
            return Err(ParseError::InvalidSyntax);
        }
        (&rest[3..], (num1, num2))
    } else {
        return Err(ParseError::InvalidSyntax);
    };

    Ok((
        rest,
        KeyPlaceholder {
            key_index,
            num1,
            num2,
        },
    ))
}

// Parses a descriptor, optionally preceded by a wrapper prefix like "asc:".
fn parse_descriptor(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    // A wrapper prefix is a run of ASCII alphabetic chars followed by ':'.
    // Fragment keywords are always followed by '(' instead, so no ambiguity.
    let alpha_end = input
        .bytes()
        .position(|b| !b.is_ascii_alphabetic())
        .unwrap_or(input.len());
    let (input, wrappers) = if alpha_end > 0 && input.as_bytes().get(alpha_end) == Some(&b':') {
        let wrappers = &input[..alpha_end];
        (&input[alpha_end + 1..], wrappers)
    } else {
        (input, "")
    };

    let (input, inner) = parse_inner_descriptor(input)?;

    // Apply wrappers in reverse character order (rightmost char = outermost wrapper)
    let mut result = inner;
    for wrapper in wrappers.chars().rev() {
        result = match wrapper {
            'a' => DescriptorTemplate::A(Box::new(result)),
            's' => DescriptorTemplate::S(Box::new(result)),
            'c' => DescriptorTemplate::C(Box::new(result)),
            't' => DescriptorTemplate::T(Box::new(result)),
            'd' => DescriptorTemplate::D(Box::new(result)),
            'v' => DescriptorTemplate::V(Box::new(result)),
            'j' => DescriptorTemplate::J(Box::new(result)),
            'n' => DescriptorTemplate::N(Box::new(result)),
            'l' => DescriptorTemplate::L(Box::new(result)),
            'u' => DescriptorTemplate::U(Box::new(result)),
            _ => return Err(ParseError::InvalidSyntax),
        };
    }
    Ok((input, result))
}

fn parse_inner_descriptor(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    // Longer names checked before shorter to avoid premature prefix matches.
    if input.starts_with("sortedmulti_a(") {
        return parse_threshold_kp_fragment(
            input,
            "sortedmulti_a",
            DescriptorTemplate::Sortedmulti_a,
        );
    }
    if input.starts_with("sortedmulti(") {
        return parse_threshold_kp_fragment(input, "sortedmulti", DescriptorTemplate::Sortedmulti);
    }
    if input.starts_with("multi_a(") {
        return parse_threshold_kp_fragment(input, "multi_a", DescriptorTemplate::Multi_a);
    }
    if input.starts_with("multi(") {
        return parse_threshold_kp_fragment(input, "multi", DescriptorTemplate::Multi);
    }
    if input.starts_with("thresh(") {
        return parse_thresh(input);
    }
    if input.starts_with("wsh(") {
        let (rest, scripts) = parse_n_subscripts(&input[4..], 1)?;
        return Ok((
            rest,
            DescriptorTemplate::Wsh(Box::new(scripts.into_iter().next().unwrap())),
        ));
    }
    if input.starts_with("sh(") {
        let (rest, scripts) = parse_n_subscripts(&input[3..], 1)?;
        return Ok((
            rest,
            DescriptorTemplate::Sh(Box::new(scripts.into_iter().next().unwrap())),
        ));
    }
    if input.starts_with("wpkh(") {
        return parse_kp_fragment(input, "wpkh", DescriptorTemplate::Wpkh);
    }
    if input.starts_with("pkh(") {
        return parse_kp_fragment(input, "pkh", DescriptorTemplate::Pkh);
    }
    if input.starts_with("tr(") {
        return parse_tr(input);
    }
    if input.starts_with("pk_k(") {
        return parse_kp_fragment(input, "pk_k", DescriptorTemplate::Pk_k);
    }
    if input.starts_with("pk_h(") {
        return parse_kp_fragment(input, "pk_h", DescriptorTemplate::Pk_h);
    }
    if input.starts_with("pk(") {
        return parse_kp_fragment(input, "pk", DescriptorTemplate::Pk);
    }
    if input.starts_with("older(") {
        return parse_num_fragment(input, "older", MAX_OLDER_AFTER, DescriptorTemplate::Older);
    }
    if input.starts_with("after(") {
        return parse_num_fragment(input, "after", MAX_OLDER_AFTER, DescriptorTemplate::After);
    }
    if input.starts_with("sha256(") {
        return parse_hex32_fragment(input, "sha256", DescriptorTemplate::Sha256);
    }
    if input.starts_with("hash256(") {
        return parse_hex32_fragment(input, "hash256", DescriptorTemplate::Hash256);
    }
    if input.starts_with("ripemd160(") {
        return parse_hex20_fragment(input, "ripemd160", DescriptorTemplate::Ripemd160);
    }
    if input.starts_with("hash160(") {
        return parse_hex20_fragment(input, "hash160", DescriptorTemplate::Hash160);
    }
    if input.starts_with("andor(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[6..], 3)?;
        let z = Box::new(scripts.remove(2));
        let y = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::Andor(x, y, z)));
    }
    if input.starts_with("and_b(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[6..], 2)?;
        let y = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::And_b(x, y)));
    }
    if input.starts_with("and_v(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[6..], 2)?;
        let y = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::And_v(x, y)));
    }
    if input.starts_with("and_n(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[6..], 2)?;
        let y = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::And_n(x, y)));
    }
    if input.starts_with("or_b(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[5..], 2)?;
        let z = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::Or_b(x, z)));
    }
    if input.starts_with("or_c(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[5..], 2)?;
        let z = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::Or_c(x, z)));
    }
    if input.starts_with("or_d(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[5..], 2)?;
        let z = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::Or_d(x, z)));
    }
    if input.starts_with("or_i(") {
        let (rest, mut scripts) = parse_n_subscripts(&input[5..], 2)?;
        let z = Box::new(scripts.remove(1));
        let x = Box::new(scripts.remove(0));
        return Ok((rest, DescriptorTemplate::Or_i(x, z)));
    }
    // Simple terminals: bare "0" and "1"
    if input.starts_with('0') {
        return Ok((&input[1..], DescriptorTemplate::Zero));
    }
    if input.starts_with('1') {
        return Ok((&input[1..], DescriptorTemplate::One));
    }
    Err(ParseError::UnrecognizedFragment)
}

// Parses a named fragment that wraps a single key placeholder: name(@...)
fn parse_kp_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn(KeyPlaceholder) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, kp) = parse_key_placeholder(&rest[1..])?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(kp)))
}

// Parses "name(n)" where n is a number <= max.
fn parse_num_fragment<'a>(
    input: &'a str,
    name: &str,
    max: u32,
    constructor: fn(u32) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len()..]; // caller already checked starts_with(name)
    let (rest, num) = parse_number_up_to(&rest[1..], max)?; // skip '('
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(num)))
}

// Parses "name(<40 hex chars>)".
fn parse_hex20_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn([u8; 20]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 40 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 20]>::from_hex(&rest[..40]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &rest[40..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "name(<64 hex chars>)".
fn parse_hex32_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn([u8; 32]) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    if rest.len() < 64 {
        return Err(ParseError::InvalidLength);
    }
    let bytes = <[u8; 32]>::from_hex(&rest[..64]).map_err(|_| ParseError::InvalidHex)?;
    let rest = &rest[64..];
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(bytes)))
}

// Parses "name(threshold,@kp1,@kp2,...)".
fn parse_threshold_kp_fragment<'a>(
    input: &'a str,
    name: &str,
    constructor: fn(u32, Vec<KeyPlaceholder>) -> DescriptorTemplate,
) -> ParseResult<'a, DescriptorTemplate> {
    let rest = &input[name.len() + 1..]; // skip name and '('
    let (mut rest, threshold) = parse_number_up_to(rest, u32::MAX)?;
    let mut keys: Vec<KeyPlaceholder> = Vec::new();
    loop {
        if !rest.starts_with(',') {
            break;
        }
        match parse_key_placeholder(&rest[1..]) {
            Ok((r, kp)) => {
                keys.push(kp);
                rest = r;
                if keys.len() == 20 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if keys.len() < 2 {
        return Err(ParseError::TooFewKeyPlaceholders);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], constructor(threshold, keys)))
}

// Parses exactly n comma-separated sub-descriptors, then ')'.
// Called after the opening '(' of the enclosing fragment has been consumed.
fn parse_n_subscripts(input: &str, n: usize) -> ParseResult<'_, Vec<DescriptorTemplate>> {
    let mut rest = input;
    let mut scripts: Vec<DescriptorTemplate> = Vec::new();
    for i in 0..n {
        let (r, desc) = parse_descriptor(rest)?;
        scripts.push(desc);
        rest = r;
        if i + 1 < n {
            if !rest.starts_with(',') {
                return Err(ParseError::InvalidSyntax);
            }
            rest = &rest[1..];
        }
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], scripts))
}

#[cfg(test)]
fn parse_wsh(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    if !input.starts_with("wsh(") {
        return Err(ParseError::InvalidSyntax);
    }
    let (rest, scripts) = parse_n_subscripts(&input[4..], 1)?;
    Ok((
        rest,
        DescriptorTemplate::Wsh(Box::new(scripts.into_iter().next().unwrap())),
    ))
}

#[cfg(test)]
fn parse_sortedmulti(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    parse_threshold_kp_fragment(input, "sortedmulti", DescriptorTemplate::Sortedmulti)
}

fn parse_thresh(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "thresh("
    let (rest, k) = parse_number_up_to(&input[7..], u32::MAX)?;
    if !rest.starts_with(',') {
        return Err(ParseError::InvalidSyntax);
    }
    // parse first script (mandatory)
    let (rest, first) = parse_descriptor(&rest[1..])?;
    let mut scripts = vec![first];
    let mut rest = rest;
    loop {
        if !rest.starts_with(',') {
            break;
        }
        match parse_descriptor(&rest[1..]) {
            Ok((r, desc)) => {
                scripts.push(desc);
                rest = r;
            }
            Err(_) => break,
        }
    }
    if (k as usize) > scripts.len() {
        return Err(ParseError::ThreshExceedsScripts);
    }
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Thresh(k, scripts)))
}

fn parse_tr(input: &str) -> ParseResult<'_, DescriptorTemplate> {
    // input starts with "tr("
    let (rest, key_placeholder) = parse_key_placeholder(&input[3..])?;
    let (rest, tree) = if rest.starts_with(',') {
        let (rest, tree) = parse_tap_tree(&rest[1..])?;
        (rest, Some(tree))
    } else {
        (rest, None)
    };
    if !rest.starts_with(')') {
        return Err(ParseError::InvalidSyntax);
    }
    Ok((&rest[1..], DescriptorTemplate::Tr(key_placeholder, tree)))
}

fn parse_tap_tree(input: &str) -> ParseResult<'_, TapTree> {
    if input.starts_with('{') {
        let (rest, left) = parse_tap_tree(&input[1..])?;
        if !rest.starts_with(',') {
            return Err(ParseError::InvalidSyntax);
        }
        let (rest, right) = parse_tap_tree(&rest[1..])?;
        if !rest.starts_with('}') {
            return Err(ParseError::InvalidSyntax);
        }
        Ok((&rest[1..], TapTree::Branch(Box::new(left), Box::new(right))))
    } else {
        let (rest, desc) = parse_descriptor(input)?;
        Ok((rest, TapTree::Script(Box::new(desc))))
    }
}

impl FromStr for DescriptorTemplate {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_descriptor_template(input)
    }
}

fn write_display_wrapper(
    f: &mut core::fmt::Formatter<'_>,
    ch: char,
    inner: &DescriptorTemplate,
) -> core::fmt::Result {
    write!(f, "{}", ch)?;
    if !inner.is_wrapper() {
        write!(f, ":")?;
    }
    write!(f, "{}", inner)
}

impl core::fmt::Display for DescriptorTemplate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DescriptorTemplate::Sh(inner) => write!(f, "sh({})", inner),
            DescriptorTemplate::Wsh(inner) => write!(f, "wsh({})", inner),
            DescriptorTemplate::Pkh(kp) => write!(f, "pkh({})", kp),
            DescriptorTemplate::Wpkh(kp) => write!(f, "wpkh({})", kp),
            DescriptorTemplate::Sortedmulti(k, kps) => {
                write!(f, "sortedmulti({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Sortedmulti_a(k, kps) => {
                write!(f, "sortedmulti_a({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Tr(kp, None) => write!(f, "tr({})", kp),
            DescriptorTemplate::Tr(kp, Some(tree)) => write!(f, "tr({},{})", kp, tree),
            DescriptorTemplate::Zero => write!(f, "0"),
            DescriptorTemplate::One => write!(f, "1"),
            DescriptorTemplate::Pk(kp) => write!(f, "pk({})", kp),
            DescriptorTemplate::Pk_k(kp) => write!(f, "pk_k({})", kp),
            DescriptorTemplate::Pk_h(kp) => write!(f, "pk_h({})", kp),
            DescriptorTemplate::Older(n) => write!(f, "older({})", n),
            DescriptorTemplate::After(n) => write!(f, "after({})", n),
            DescriptorTemplate::Sha256(hash) => write!(f, "sha256({})", hex::encode(hash)),
            DescriptorTemplate::Ripemd160(hash) => write!(f, "ripemd160({})", hex::encode(hash)),
            DescriptorTemplate::Hash256(hash) => write!(f, "hash256({})", hex::encode(hash)),
            DescriptorTemplate::Hash160(hash) => write!(f, "hash160({})", hex::encode(hash)),
            DescriptorTemplate::Andor(x, y, z) => write!(f, "andor({},{},{})", x, y, z),
            DescriptorTemplate::And_v(x, y) => write!(f, "and_v({},{})", x, y),
            DescriptorTemplate::And_b(x, y) => write!(f, "and_b({},{})", x, y),
            DescriptorTemplate::And_n(x, y) => write!(f, "and_n({},{})", x, y),
            DescriptorTemplate::Or_b(x, y) => write!(f, "or_b({},{})", x, y),
            DescriptorTemplate::Or_c(x, y) => write!(f, "or_c({},{})", x, y),
            DescriptorTemplate::Or_d(x, y) => write!(f, "or_d({},{})", x, y),
            DescriptorTemplate::Or_i(x, y) => write!(f, "or_i({},{})", x, y),
            DescriptorTemplate::Thresh(k, descs) => {
                write!(f, "thresh({}", k)?;
                for desc in descs {
                    write!(f, ",{}", desc)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Multi(k, kps) => {
                write!(f, "multi({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::Multi_a(k, kps) => {
                write!(f, "multi_a({}", k)?;
                for kp in kps {
                    write!(f, ",{}", kp)?;
                }
                write!(f, ")")
            }
            DescriptorTemplate::A(inner) => write_display_wrapper(f, 'a', inner),
            DescriptorTemplate::S(inner) => write_display_wrapper(f, 's', inner),
            DescriptorTemplate::C(inner) => write_display_wrapper(f, 'c', inner),
            DescriptorTemplate::T(inner) => write_display_wrapper(f, 't', inner),
            DescriptorTemplate::D(inner) => write_display_wrapper(f, 'd', inner),
            DescriptorTemplate::V(inner) => write_display_wrapper(f, 'v', inner),
            DescriptorTemplate::J(inner) => write_display_wrapper(f, 'j', inner),
            DescriptorTemplate::N(inner) => write_display_wrapper(f, 'n', inner),
            DescriptorTemplate::L(inner) => write_display_wrapper(f, 'l', inner),
            DescriptorTemplate::U(inner) => write_display_wrapper(f, 'u', inner),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalletPolicy {
    pub descriptor_template: DescriptorTemplate,
    pub key_information: Vec<KeyInformation>,

    descriptor_template_raw: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SegwitVersion {
    Legacy,
    SegwitV0,
    Taproot,
}

impl SegwitVersion {
    pub fn is_segwit(&self) -> bool {
        matches!(self, SegwitVersion::SegwitV0 | SegwitVersion::Taproot)
    }
}

impl WalletPolicy {
    pub fn new(
        descriptor_template_str: &str,
        key_information: Vec<KeyInformation>,
    ) -> Result<Self, ParseError> {
        let descriptor_template = DescriptorTemplate::from_str(descriptor_template_str)?;

        Ok(Self {
            descriptor_template,
            key_information,
            descriptor_template_raw: String::from(descriptor_template_str),
        })
    }

    pub fn descriptor_template_raw(&self) -> &str {
        &self.descriptor_template_raw
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        let len = VarInt(self.descriptor_template_raw().len() as u64);
        len.consensus_encode(&mut result).unwrap();
        result.extend_from_slice(self.descriptor_template_raw().as_bytes());

        // number of keys
        VarInt(self.key_information.len() as u64)
            .consensus_encode(&mut result)
            .unwrap();
        for key_info in &self.key_information {
            // serialize key information
            match &key_info.origin_info {
                None => {
                    result.push(0);
                }
                Some(k) => {
                    result.push(1);
                    result.extend_from_slice(&k.fingerprint.to_be_bytes());
                    VarInt(k.derivation_path.len() as u64)
                        .consensus_encode(&mut result)
                        .unwrap();
                    for step in k.derivation_path.iter() {
                        result.extend_from_slice(&u32::from(*step).to_le_bytes());
                    }
                }
            }
            // serialize pubkey
            result.extend_from_slice(&key_info.pubkey.encode());
        }

        result
    }

    pub fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Deserialize descriptor template.
        let VarInt(desc_len) = VarInt::consensus_decode(r)?;
        let mut desc_bytes = vec![0u8; desc_len as usize];
        r.read_exact(&mut desc_bytes)?;
        let descriptor_template_str = String::from_utf8(desc_bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid UTF-8 in descriptor"))?;

        // Deserialize key_information vector.
        let VarInt(key_count) = VarInt::consensus_decode(r)?;
        let mut key_information = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let origin_info = match flag[0] {
                0 => None,
                1 => {
                    let mut fp_buf = [0; 4];
                    r.read_exact(&mut fp_buf)?;
                    let fingerprint = u32::from_be_bytes(fp_buf);
                    let VarInt(dp_len) = VarInt::consensus_decode(r)?;
                    let mut derivation_path = Vec::with_capacity(dp_len as usize);
                    for _ in 0..dp_len {
                        let mut step_bytes = [0u8; 4];
                        r.read_exact(&mut step_bytes)?;
                        derivation_path.push(ChildNumber::from(u32::from_le_bytes(step_bytes)));
                    }
                    Some(KeyOrigin {
                        fingerprint,
                        derivation_path,
                    })
                }
                _ => {
                    return Err(encode::Error::ParseFailed("Invalid key information flag"));
                }
            };
            // Deserialize pubkey.
            let mut xpub_bytes = vec![0u8; 78];
            r.read_exact(&mut xpub_bytes)?;

            key_information.push(KeyInformation {
                origin_info,
                pubkey: Xpub::decode(&xpub_bytes)
                    .map_err(|_| encode::Error::ParseFailed("Invalid xpub"))?,
            });
        }

        // test that the stream is indeed exhausted
        let mut buf = [0u8; 1];
        match r.read(&mut buf)? {
            0 => {}
            _ => {
                return Err(encode::Error::ParseFailed(
                    "Extra data after deserializing WalletPolicy",
                ));
            }
        }

        Ok(
            WalletPolicy::new(&descriptor_template_str, key_information).map_err(|_| {
                encode::Error::ParseFailed("Invalid descriptor template or key information")
            })?,
        )
    }

    pub fn get_segwit_version(&self) -> Result<SegwitVersion, ParseError> {
        match &self.descriptor_template {
            DescriptorTemplate::Tr(_, _) => Ok(SegwitVersion::Taproot),
            DescriptorTemplate::Pkh(_) => Ok(SegwitVersion::Legacy),
            DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => Ok(SegwitVersion::SegwitV0),
            DescriptorTemplate::Sh(inner) => match inner.as_ref() {
                DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => {
                    Ok(SegwitVersion::SegwitV0)
                }
                _ => Ok(SegwitVersion::Legacy),
            },
            _ => Err(ParseError::InvalidTopLevelPolicy),
        }
    }

    // TODO: move this to app code
    //     /// Checks whether this policy is a single-sig policy where both the descriptor and the
    //     /// single key path (which must be present) is according to BIP-44, BIP-49, BIP-84, or
    //     /// BIP-86 specifications.
    //     /// Default policies are the ones that can be used without registering them first.
    //     ///
    //     /// Note that this does not verify that the xpub is indeed derived as claimed; the
    //     /// responsibility for this check is on the caller.
    //     pub fn is_default(&self) -> bool {
    //         if self.key_information.len() != 1 {
    //             return false;
    //         }

    //         let key_origin = match &self.key_information[0].origin_info {
    //             Some(ko) => ko,
    //             None => return false,
    //         };

    //         if key_origin.derivation_path.len() != 3 {
    //             return false;
    //         }

    //         // checks if a key placeholder is canonical
    //         fn check_kp(kp: &KeyPlaceholder) -> bool {
    //             kp.key_index == 0 && kp.num1 == 0 && kp.num2 == 1
    //         }

    //         // checks if a derivation path is canonical according to the BIP-44 purpose
    //         fn check_path(der_path: &[ChildNumber], purpose: u32) -> bool {
    //             const H: u32 = 0x80000000u32;

    //             der_path.len() == 3
    //                 && der_path[..2]
    //                     == vec![
    //                         ChildNumber::from_hardened_idx(purpose).unwrap(),
    //                         ChildNumber::from_hardened_idx(BIP44_COIN_TYPE).unwrap(),
    //                     ]
    //                 && der_path[2].is_hardened()
    //                 && der_path[2]
    //                     <= ChildNumber::from_hardened_idx(MAX_BIP44_ACCOUNT_RECOMMENDED).unwrap()
    //         }

    //         match &self.descriptor_template {
    //             DescriptorTemplate::Pkh(kp) => {
    //                 // BIP-44
    //                 check_kp(kp) && check_path(&key_origin.derivation_path, 44)
    //             }
    //             DescriptorTemplate::Wpkh(kp) => {
    //                 // BIP-84
    //                 check_kp(kp) && check_path(&key_origin.derivation_path, 84)
    //             }
    //             DescriptorTemplate::Sh(inner) => match inner.as_ref() {
    //                 DescriptorTemplate::Wpkh(kp) => {
    //                     // BIP-49
    //                     check_kp(kp) && check_path(&key_origin.derivation_path, 49)
    //                 }
    //                 _ => false,
    //             },
    //             DescriptorTemplate::Tr(kp, tree) => {
    //                 // BIP-86
    //                 tree.is_none() && check_kp(kp) && check_path(&key_origin.derivation_path, 86)
    //             }
    //             _ => false,
    //         }
    //     }
}

fn write_key_placeholder(
    w: &mut String,
    key_information: &[KeyInformation],
    kp: &KeyPlaceholder,
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    use core::fmt::Write;
    let key_info = key_information
        .get(kp.key_index as usize)
        .ok_or(ParseError::InvalidKeyIndex)?;
    let change_step = if is_change { kp.num2 } else { kp.num1 };
    write!(w, "{}/{}/{}", key_info, change_step, address_index).map_err(|_| ParseError::FormatError)
}

// Writes a comma-separated list of key placeholders to a buffer.
fn write_key_placeholders(
    w: &mut String,
    key_information: &[KeyInformation],
    kps: &[KeyPlaceholder],
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    for (i, kp) in kps.iter().enumerate() {
        if i > 0 {
            w.push(',');
        }
        write_key_placeholder(w, key_information, kp, is_change, address_index)?;
    }
    Ok(())
}

// Writes a wrapper fragment to a buffer.
fn write_wrapper(
    w: &mut String,
    name: &str,
    inner: &DescriptorTemplate,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<(), ParseError> {
    w.push_str(name);
    if !inner.is_wrapper() {
        w.push(':');
    }
    inner.write_to(w, key_information, is_change, address_index)
}

impl TapTree {
    fn write_to(
        &self,
        w: &mut String,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<(), ParseError> {
        match self {
            TapTree::Script(desc) => desc.write_to(w, key_information, is_change, address_index),
            TapTree::Branch(left, right) => {
                w.push('{');
                left.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                right.write_to(w, key_information, is_change, address_index)?;
                w.push('}');
                Ok(())
            }
        }
    }
}

impl DescriptorTemplate {
    fn write_to(
        &self,
        w: &mut String,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<(), ParseError> {
        use core::fmt::Write;

        match self {
            DescriptorTemplate::Sh(inner) => {
                w.push_str("sh(");
                inner.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Wsh(inner) => {
                w.push_str("wsh(");
                inner.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pkh(kp) => {
                w.push_str("pkh(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Wpkh(kp) => {
                w.push_str("wpkh(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti(threshold, kps) => {
                write!(w, "sortedmulti({}, ", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_placeholders(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Sortedmulti_a(threshold, kps) => {
                write!(w, "sortedmulti_a({}, ", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_placeholders(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Tr(kp, tap_tree) => {
                w.push_str("tr(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                if let Some(tree) = tap_tree {
                    w.push_str(", ");
                    tree.write_to(w, key_information, is_change, address_index)?;
                }
                w.push(')');
            }
            DescriptorTemplate::Zero => w.push('0'),
            DescriptorTemplate::One => w.push('1'),
            DescriptorTemplate::Pk(kp) => {
                w.push_str("pk(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_k(kp) => {
                w.push_str("pk_k(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Pk_h(kp) => {
                w.push_str("pk_h(");
                write_key_placeholder(w, key_information, kp, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Older(n) => {
                write!(w, "older({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::After(n) => {
                write!(w, "after({})", n).map_err(|_| ParseError::FormatError)?;
            }
            DescriptorTemplate::Sha256(hash) => {
                w.push_str("sha256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Ripemd160(hash) => {
                w.push_str("ripemd160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash256(hash) => {
                w.push_str("hash256(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Hash160(hash) => {
                w.push_str("hash160(");
                w.push_str(&hex::encode(hash));
                w.push(')');
            }
            DescriptorTemplate::Andor(x, y, z) => {
                w.push_str("andor(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_v(x, y) => {
                w.push_str("and_v(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_b(x, y) => {
                w.push_str("and_b(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::And_n(x, y) => {
                w.push_str("and_n(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                y.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_b(x, z) => {
                w.push_str("or_b(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_c(x, z) => {
                w.push_str("or_c(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_d(x, z) => {
                w.push_str("or_d(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Or_i(x, z) => {
                w.push_str("or_i(");
                x.write_to(w, key_information, is_change, address_index)?;
                w.push(',');
                z.write_to(w, key_information, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Thresh(k, sub_templates) => {
                write!(w, "thresh({},[", k).map_err(|_| ParseError::FormatError)?;
                for (i, template) in sub_templates.iter().enumerate() {
                    if i > 0 {
                        w.push(',');
                    }
                    template.write_to(w, key_information, is_change, address_index)?;
                }
                w.push_str("])");
            }
            DescriptorTemplate::Multi(threshold, kps) => {
                write!(w, "multi({}, ", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_placeholders(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::Multi_a(threshold, kps) => {
                write!(w, "multi_a({}, ", threshold).map_err(|_| ParseError::FormatError)?;
                write_key_placeholders(w, key_information, kps, is_change, address_index)?;
                w.push(')');
            }
            DescriptorTemplate::A(inner) => {
                write_wrapper(w, "a", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::S(inner) => {
                write_wrapper(w, "s", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::C(inner) => {
                write_wrapper(w, "c", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::T(inner) => {
                write_wrapper(w, "t", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::D(inner) => {
                write_wrapper(w, "d", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::V(inner) => {
                write_wrapper(w, "v", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::J(inner) => {
                write_wrapper(w, "j", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::N(inner) => {
                write_wrapper(w, "n", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::L(inner) => {
                write_wrapper(w, "l", inner, key_information, is_change, address_index)?;
            }
            DescriptorTemplate::U(inner) => {
                write_wrapper(w, "u", inner, key_information, is_change, address_index)?;
            }
        }
        Ok(())
    }
}

impl ToDescriptor for TapTree {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.write_to(&mut result, key_information, is_change, address_index)?;
        Ok(result)
    }
}

impl ToDescriptor for DescriptorTemplate {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let mut result = String::new();
        self.write_to(&mut result, key_information, is_change, address_index)?;
        Ok(result)
    }
}

// TODO: add tests for to_descriptor

#[cfg(test)]
mod tests {
    use super::*;

    const H: u32 = HARDENED_INDEX;
    const MAX_STEP: &'static str = "2147483647";
    const MAX_STEP_H: &'static str = "2147483647'";

    #[test]
    fn test_parse_derivation_step_number() {
        let test_cases_success = vec![
            ("0", ("", 0)),
            ("0'", ("", H)),
            ("1", ("", 1)),
            ("1'", ("", 1 + H)),
            (MAX_STEP, ("", H - 1)),
            (MAX_STEP_H, ("", H - 1 + H)),
            // only ' is supported as hardened symbol, so this must leave the h or H unparsed
            ("5h", ("h", 5)),
            ("5H", ("H", 5)),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_derivation_step_number(input);
            assert_eq!(result, Ok(expected));
        }

        let test_cases_err = vec!["", "a", stringify!(H), concat!(stringify!(H), "'")];

        for input in test_cases_err {
            assert!(parse_derivation_step_number(input).is_err());
        }
    }

    fn make_key_origin_info(fpr: u32, der_path: Vec<u32>) -> KeyOrigin {
        KeyOrigin {
            fingerprint: fpr,
            derivation_path: der_path.into_iter().map(ChildNumber::from).collect(),
        }
    }

    fn koi(key_origin_str: &str) -> KeyInformation {
        KeyInformation::try_from(key_origin_str).unwrap()
    }

    #[test]
    fn test_parse_key_origin() {
        let test_cases_success = vec![
            (
                "012345af/0'/1'/3",
                make_key_origin_info(0x012345af, vec![0 + H, 1 + H, 3]),
            ),
            (
                "012345af/2147483647'/1'/3/6/7/42/12/54/23/56/89",
                make_key_origin_info(
                    0x012345af,
                    vec![2147483647 + H, 1 + H, 3, 6, 7, 42, 12, 54, 23, 56, 89],
                ),
            ),
            ("012345af", make_key_origin_info(0x012345af, vec![])),
        ];

        for (input, expected) in test_cases_success {
            assert_eq!(KeyOrigin::try_from(input), Ok(expected));
        }

        let test_cases_err = vec![
            "[01234567/0'/1'/3]",
            "0123456/0'/1'/3",
            "012345678/0'/1'/3",
            "012345ag/0'/1'/2147483648",
        ];

        for input in test_cases_err {
            assert!(KeyOrigin::try_from(input).is_err());
        }
    }

    #[test]
    fn test_parse_key_placeholder() {
        let test_cases_success = vec![
            (
                "@0/**",
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
            ),
            (
                "@4294967295/**",
                KeyPlaceholder {
                    key_index: 4294967295,
                    num1: 0,
                    num2: 1,
                },
            ), // u32::MAX
            (
                "@1/<0;1>/*",
                KeyPlaceholder {
                    key_index: 1,
                    num1: 0,
                    num2: 1,
                },
            ),
            (
                "@2/<3;4>/*",
                KeyPlaceholder {
                    key_index: 2,
                    num1: 3,
                    num2: 4,
                },
            ),
            (
                "@3/<1;9>/*",
                KeyPlaceholder {
                    key_index: 3,
                    num1: 1,
                    num2: 9,
                },
            ),
        ];

        for (input, expected) in test_cases_success {
            let result = parse_key_placeholder(input);
            assert_eq!(result, Ok(("", expected)));
        }

        let test_cases_err = vec![
            "@0",
            "@0**",
            "@a/**",
            "@0/*",
            "@0/<0;1>",       // missing /*
            "@0/<0,1>/*",     // , instead of ;
            "@4294967296/**", // too large
            "0/**",
        ];

        for input in test_cases_err {
            assert!(parse_key_placeholder(input).is_err());
        }
    }

    #[test]
    fn test_parse_sortedmulti() {
        let input = "sortedmulti(2,@0/**,@1/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Sortedmulti(
                2,
                vec![
                    KeyPlaceholder {
                        key_index: 0,
                        num1: 0,
                        num2: 1,
                    },
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                ],
            ),
        ));
        assert_eq!(parse_sortedmulti(input), expected);
    }

    #[test]
    fn test_parse_wsh_sortedmulti() {
        let input = "wsh(sortedmulti(2,@0/**,@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Wsh(Box::new(DescriptorTemplate::Sortedmulti(
                2,
                vec![
                    KeyPlaceholder {
                        key_index: 0,
                        num1: 0,
                        num2: 1,
                    },
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                ],
            ))),
        ));
        assert_eq!(parse_wsh(input), expected);
    }

    #[test]
    fn test_parse_tr() {
        let input = "tr(@0/**)";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
                None,
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        let input = "tr(@0/**,pkh(@1/**))";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 0,
                    num2: 1,
                },
                Some(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                    KeyPlaceholder {
                        key_index: 1,
                        num1: 0,
                        num2: 1,
                    },
                )))),
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        let input = "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),sh(wpkh(@2/**))})";
        let expected = Ok((
            "",
            DescriptorTemplate::Tr(
                KeyPlaceholder {
                    key_index: 0,
                    num1: 2,
                    num2: 1,
                },
                Some(TapTree::Branch(
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Pkh(
                        KeyPlaceholder {
                            key_index: 1,
                            num1: 2,
                            num2: 7,
                        },
                    )))),
                    Box::new(TapTree::Script(Box::new(DescriptorTemplate::Sh(Box::new(
                        DescriptorTemplate::Wpkh(KeyPlaceholder {
                            key_index: 2,
                            num1: 0,
                            num2: 1,
                        }),
                    ))))),
                )),
            ),
        ));
        assert_eq!(parse_tr(input), expected);

        // failure cases
        assert!(parse_tr("tr(@0/**,)").is_err());
        assert!(parse_tr("tr(pkh(@0/**))").is_err());
        assert!(parse_tr("tr(@0))").is_err());
        assert!(parse_tr("tr(@0/*))").is_err());
        assert!(parse_tr("tr(@0/*/0)").is_err());
    }

    #[test]
    fn test_parse_valid_descriptor_templates() {
        assert!(parse_descriptor("sln:older(12960)").is_ok());
        assert!(
            parse_thresh("thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960))").is_ok()
        );

        let test_cases = vec![
            "wsh(sortedmulti(2,@0/**,@1/**))",
            "sh(wsh(sortedmulti(2,@0/**,@1/**)))",
            "wsh(c:pk_k(@0/**))",
            "wsh(or_d(pk(@0/**),pkh(@1/**)))",
            "wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@2/**),sln:older(12960)))",
        ];

        for input in test_cases {
            let result = parse_descriptor_template(input);
            assert!(result.is_ok())
        }
    }

    #[test]
    fn test_wallet_policy() {
        let wallet = WalletPolicy::new(
            &"sh(wsh(sortedmulti(2,@0/**,@1/**)))".to_string(),
            vec![
                koi("[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g"),
                koi("[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY"),
            ]
        );

        assert!(wallet.is_ok());
    }

    // TODO" move elsewhere
    // #[test]
    // fn test_wallet_policy_is_default() {
    //     let valid_combos: Vec<(&str, u32)> = vec![
    //         ("pkh(@0/**)", 44),
    //         ("sh(wpkh(@0/**))", 49),
    //         ("wpkh(@0/**)", 84),
    //         ("tr(@0/**)", 86),
    //     ];

    //     // we re-use the same dummy tpub for all tests - it's not checked anyway
    //     let dummy_key = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";

    //     for (desc_tmp, purpose) in &valid_combos {
    //         // test valid cases
    //         for account in [0, 1, 50, MAX_BIP44_ACCOUNT_RECOMMENDED] {
    //             assert_eq!(
    //                 WalletPolicy::new(
    //                     desc_tmp,
    //                     vec![koi(&format!(
    //                         "[f5acc2fd/{}'/{}'/{}']{}",
    //                         purpose, BIP44_COIN_TYPE, account, dummy_key
    //                     ))]
    //                 )
    //                 .unwrap()
    //                 .is_default(),
    //                 true
    //             );
    //         }

    //         // test invalid purposes (using the "purpose" from the wrong BIP)
    //         for (_, invalid_purpose) in valid_combos.iter().filter(|(_, p)| p != purpose) {
    //             assert_eq!(
    //                 WalletPolicy::new(
    //                     desc_tmp,
    //                     vec![koi(&format!(
    //                         "[f5acc2fd/{}'/{}'/{}']{}",
    //                         invalid_purpose, BIP44_COIN_TYPE, 0, dummy_key
    //                     ))]
    //                 )
    //                 .unwrap()
    //                 .is_default(),
    //                 false
    //             );
    //         }

    //         // test account too large
    //         assert_eq!(
    //             WalletPolicy::new(
    //                 desc_tmp,
    //                 vec![koi(&format!(
    //                     "[f5acc2fd/{}'/{}'/{}']{}",
    //                     purpose,
    //                     BIP44_COIN_TYPE,
    //                     MAX_BIP44_ACCOUNT_RECOMMENDED + 1,
    //                     dummy_key
    //                 ))]
    //             )
    //             .unwrap()
    //             .is_default(),
    //             false
    //         );

    //         // test unhardened purpose
    //         assert_eq!(
    //             WalletPolicy::new(
    //                 desc_tmp,
    //                 vec![koi(&format!(
    //                     "[f5acc2fd/{}/{}'/{}']{}",
    //                     44, BIP44_COIN_TYPE, 0, dummy_key
    //                 ))]
    //             )
    //             .unwrap()
    //             .is_default(),
    //             false
    //         );

    //         // test unhardened coin_type
    //         assert_eq!(
    //             WalletPolicy::new(
    //                 desc_tmp,
    //                 vec![koi(&format!(
    //                     "[f5acc2fd/{}'/{}/{}']{}",
    //                     44, BIP44_COIN_TYPE, 0, dummy_key
    //                 ))]
    //             )
    //             .unwrap()
    //             .is_default(),
    //             false
    //         );

    //         // test unhardened account
    //         assert_eq!(
    //             WalletPolicy::new(
    //                 desc_tmp,
    //                 vec![koi(&format!(
    //                     "[f5acc2fd/{}'/{}/{}']{}",
    //                     44, BIP44_COIN_TYPE, 0, dummy_key
    //                 ))]
    //             )
    //             .unwrap()
    //             .is_default(),
    //             false
    //         );

    //         // test missing key origin
    //         assert_eq!(
    //             WalletPolicy::new(desc_tmp, vec![koi(&dummy_key)])
    //                 .unwrap()
    //                 .is_default(),
    //             false
    //         );
    //     }

    //     // tr with non-empty script is not standard
    //     assert_eq!(
    //         WalletPolicy::new(
    //             "tr(@0/**,0)",
    //             vec![koi(&format!(
    //                 "[f5acc2fd/86'/{}'/{}']{}",
    //                 BIP44_COIN_TYPE, 0, dummy_key
    //             ))]
    //         )
    //         .unwrap()
    //         .is_default(),
    //         false
    //     );
    // }

    #[test]
    fn test_descriptortemplate_placeholders_iterator() {
        fn format_kp(kp: &KeyPlaceholder) -> String {
            format!("@{}/<{};{}>/*", kp.key_index, kp.num1, kp.num2)
        }

        struct TestCase {
            descriptor: &'static str,
            expected: Vec<&'static str>,
        }
        impl TestCase {
            fn new(descriptor: &'static str, expected: &[&'static str]) -> Self {
                Self {
                    descriptor,
                    expected: Vec::from(expected),
                }
            }
        }

        // Define a list of test cases
        let test_cases = vec![
            TestCase::new("0", &[]),
            TestCase::new("after(12345)", &[]),
            TestCase::new("pkh(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new("wpkh(@0/<11;67>/*)", &["@0/<11;67>/*"]),
            TestCase::new("tr(@0/**)", &["@0/<0;1>/*"]),
            TestCase::new(
                "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
                &["@4/<3;7>/*", "@0/<0;1>/*", "@3/<0;1>/*", "@5/<99;101>/*", "@1/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*"]
            ),
            TestCase::new(
                "tr(@0/**,{{{sortedmulti_a(1,@1/**,@2/**,@3/**,@4/**,@5/**),multi_a(2,@6/**,@7/**,@8/**)},{multi_a(2,@9/**,@10/**,@11/**,@12/**),pk(@13/**)}},{{multi_a(2,@14/**,@15/**),multi_a(3,@16/**,@17/**,@18/**)},{multi_a(2,@19/**,@20/**),pk(@21/**)}}})",
                &["@0/<0;1>/*", "@1/<0;1>/*", "@2/<0;1>/*", "@3/<0;1>/*", "@4/<0;1>/*", "@5/<0;1>/*", "@6/<0;1>/*", "@7/<0;1>/*", "@8/<0;1>/*", "@9/<0;1>/*", "@10/<0;1>/*", "@11/<0;1>/*", "@12/<0;1>/*", "@13/<0;1>/*", "@14/<0;1>/*", "@15/<0;1>/*", "@16/<0;1>/*", "@17/<0;1>/*", "@18/<0;1>/*", "@19/<0;1>/*", "@20/<0;1>/*", "@21/<0;1>/*"]
            ),
        ];

        for case in test_cases {
            let desc = DescriptorTemplate::from_str(case.descriptor).unwrap();
            let iter = DescriptorTemplateIter::from(&desc);
            let results: Vec<_> = iter.map(|(k, _)| format_kp(k)).collect();

            assert_eq!(results, case.expected);
        }
    }

    #[test]
    fn test_display_roundtrip() {
        let cases = vec![
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
            "tr(@0/<2;1>/*,{pkh(@1/<2;7>/*),sh(wpkh(@2/**))})",
            "after(12345)",
            "older(65535)",
            "sha256(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "ripemd160(aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)",
            "hash256(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "hash160(bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)",
            "wsh(andor(pk(@0/**),older(1),pk(@1/**)))",
            "wsh(or_i(and_v(v:pkh(@4/<3;7>/*),older(65535)),or_d(multi(2,@0/**,@3/**),and_v(v:thresh(1,pkh(@5/<99;101>/*),a:pkh(@1/**)),older(64231)))))",
            "tr(@0/**,{sortedmulti_a(1,@1/**,@2/**),or_b(pk(@3/**),s:pk(@4/**))})",
        ];

        for s in cases {
            let parsed = DescriptorTemplate::from_str(s)
                .unwrap_or_else(|e| panic!("parse failed for {:?}: {:?}", s, e));
            let displayed = parsed.to_string();
            assert_eq!(displayed, s, "roundtrip failed for {:?}", s);
        }
    }
}
