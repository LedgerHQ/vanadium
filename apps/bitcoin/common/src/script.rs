use alloc::{boxed::Box, vec::Vec};

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::opcodes::{all::*, OP_0};
use bitcoin::script::Builder;
use bitcoin::{PubkeyHash, ScriptBuf, ScriptHash, TapNodeHash, WPubkeyHash, WScriptHash};

use bip388::arena::{ArenaRead, Cursor, DescriptorNode, KeyListView, KeyView};

use crate::errors::Error;
use crate::taproot::GetTapTreeHash;

// Simple generic bubble sort implementation for Vec<[u8; N]>.
trait BubbleSort {
    fn bubble_sort(&mut self);
}

impl<const N: usize> BubbleSort for Vec<[u8; N]> {
    fn bubble_sort(&mut self) {
        let len = self.len();
        if len < 2 {
            return;
        }
        for i in 0..len {
            let mut swapped = false;
            for j in 0..(len - 1 - i) {
                if self[j] > self[j + 1] {
                    self.swap(j, j + 1);
                    swapped = true;
                }
            }
            if !swapped {
                break;
            }
        }
    }
}

use crate::account::{DescriptorTemplate, KeyExpression, KeyInformation, WalletPolicy};

const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const MAX_PUBKEYS_PER_MULTI_A: usize = 999;

pub trait ToScript {
    fn to_script(&self, is_change: bool, address_index: u32) -> Result<ScriptBuf, Error>;
}

pub trait ToScriptWithKeyInfo {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<ScriptBuf, Error>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ScriptContext {
    None,
    Sh,
    Wsh,
    Tr,
}

// TODO: refactoring this as a method of Builder might simplify the code
trait ToScriptWithKeyInfoInner {
    fn to_script_inner(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        builder: Builder,
        ctx: ScriptContext,
    ) -> Result<Builder, Error>;
}

trait CanPushInnerScript {
    fn push_inner_script(
        self,
        desc: &DescriptorTemplate,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, Error>;
}

impl CanPushInnerScript for Builder {
    fn push_inner_script(
        self,
        desc: &DescriptorTemplate,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, Error> {
        desc.to_script_inner(key_information, is_change, address_index, self, ctx)
    }
}

impl ToScriptWithKeyInfoInner for DescriptorTemplate {
    fn to_script_inner(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        mut builder: Builder,
        ctx: ScriptContext,
    ) -> Result<Builder, Error> {
        let derive = |kp: &KeyExpression| -> Result<Xpub, Error> {
            let change_step = ChildNumber::from(if is_change { kp.num2 } else { kp.num1 });
            let path = [change_step, ChildNumber::from(address_index)];
            let secp = bitcoin::secp256k1::Secp256k1::new();

            // Resolve the root xpub of the key expression: either a single
            // participant's xpub (plain) or the BIP-388 aggregate of several
            // participants' xpubs (musig).
            let root_xpub: Xpub = if let Some(idx) = kp.plain_key_index() {
                key_information
                    .get(idx as usize)
                    .ok_or(Error::InvalidKeyIndex)?
                    .pubkey
            } else if let Some(indices) = kp.musig_key_indices() {
                let participant_xpubs: Vec<Xpub> = indices
                    .iter()
                    .map(|&i| {
                        key_information
                            .get(i as usize)
                            .map(|ki| ki.pubkey)
                            .ok_or(Error::InvalidKeyIndex)
                    })
                    .collect::<Result<_, _>>()?;
                crate::musig::aggregate_xpub(&participant_xpubs).map_err(|_| Error::InvalidKey)?
            } else {
                return Err(Error::UnsupportedWalletPolicy);
            };

            root_xpub
                .derive_pub(&secp, &path)
                .map_err(|_| Error::InvalidKey)
        };

        builder = match self {
            DescriptorTemplate::Sh(inner) => {
                if ctx != ScriptContext::None && ctx != ScriptContext::Wsh {
                    return Err(Error::InvalidScriptContext);
                }

                let mut inner_builder = Builder::new();
                inner_builder = inner.to_script_inner(
                    key_information,
                    is_change,
                    address_index,
                    inner_builder,
                    ScriptContext::Sh,
                )?;

                let script_hash =
                    ScriptHash::from_raw_hash(hash160::Hash::hash(&inner_builder.as_bytes()));

                builder
                    .push_opcode(OP_HASH160)
                    .push_slice(script_hash)
                    .push_opcode(OP_EQUAL)
            }
            DescriptorTemplate::Wsh(inner) => {
                if ctx != ScriptContext::None {
                    return Err(Error::InvalidScriptContext);
                }

                let mut inner_builder = Builder::new();
                inner_builder = inner.to_script_inner(
                    key_information,
                    is_change,
                    address_index,
                    inner_builder,
                    ScriptContext::Wsh,
                )?;
                let script_hash =
                    WScriptHash::from_raw_hash(sha256::Hash::hash(&inner_builder.as_bytes()));
                builder.push_int(0).push_slice(script_hash)
            }
            DescriptorTemplate::Pkh(kp) => {
                let key = derive(kp)?;
                let pubkey: Vec<u8> = if ctx == ScriptContext::Tr {
                    key.to_x_only_pub().serialize().to_vec()
                } else {
                    key.to_pub().to_bytes().to_vec()
                };

                let pubkey_hash = PubkeyHash::from_raw_hash(hash160::Hash::hash(&pubkey));

                builder
                    .push_opcode(OP_DUP)
                    .push_opcode(OP_HASH160)
                    .push_slice(pubkey_hash)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_opcode(OP_CHECKSIG)
            }
            DescriptorTemplate::Wpkh(kp) => {
                if ctx != ScriptContext::None && ctx != ScriptContext::Sh {
                    return Err(Error::InvalidScriptContext);
                }

                let pubkey = derive(kp)?.public_key.serialize();
                let pubkey_hash = WPubkeyHash::from_raw_hash(hash160::Hash::hash(&pubkey));
                builder.push_int(0).push_slice(pubkey_hash)
            }
            DescriptorTemplate::Sortedmulti(k, kps) | DescriptorTemplate::Multi(k, kps) => {
                if ctx == ScriptContext::Tr {
                    return Err(Error::InvalidScriptContext);
                }

                if kps.len() > MAX_PUBKEYS_PER_MULTISIG {
                    return Err(Error::TooManyKeys);
                }
                if *k == 0 || (*k as usize) > kps.len() {
                    return Err(Error::InvalidMultisigQuorum);
                }

                builder = builder.push_int(*k as i64);

                let mut keys = kps
                    .iter()
                    .map(|kp| derive(kp))
                    .map(|derived_key_result| {
                        derived_key_result
                            .map(|extended_pub_key| extended_pub_key.to_pub().to_bytes())
                    })
                    .collect::<Result<Vec<[u8; 33]>, Error>>()?;

                if matches!(self, DescriptorTemplate::Sortedmulti(_, _)) {
                    // O(n^2) sorting, better for small arrays
                    keys.bubble_sort();
                }

                for key in keys {
                    builder = builder.push_slice(&key);
                }

                builder
                    .push_int(kps.len() as i64) // TODO: check if correct
                    .push_opcode(OP_CHECKMULTISIG)
            }
            DescriptorTemplate::Sortedmulti_a(k, kps) | DescriptorTemplate::Multi_a(k, kps) => {
                if ctx != ScriptContext::Tr {
                    return Err(Error::InvalidScriptContext);
                }

                if kps.len() > MAX_PUBKEYS_PER_MULTI_A {
                    return Err(Error::TooManyKeys);
                }
                if *k == 0 || (*k as usize) > kps.len() {
                    return Err(Error::InvalidMultisigQuorum);
                }

                let mut keys = kps
                    .iter()
                    .map(|kp| derive(kp))
                    .map(|derived_key_result| {
                        derived_key_result.map(|extended_pub_key| {
                            extended_pub_key
                                .public_key
                                .x_only_public_key()
                                .0
                                .serialize()
                        })
                    })
                    .collect::<Result<Vec<[u8; 32]>, Error>>()?;

                if matches!(self, DescriptorTemplate::Sortedmulti_a(_, _)) {
                    // O(n^2) sorting, better for small arrays
                    keys.bubble_sort();
                }

                for (idx, key) in keys.iter().enumerate() {
                    builder = builder.push_slice(key);

                    if idx == 0 {
                        builder = builder.push_opcode(OP_CHECKSIG);
                    } else {
                        builder = builder.push_opcode(OP_CHECKSIGADD);
                    }
                }

                builder.push_int(*k as i64).push_opcode(OP_NUMEQUAL)
            }
            DescriptorTemplate::Tr(k, tree) => {
                let secp = bitcoin::secp256k1::Secp256k1::new();
                let internal_key: UntweakedPublicKey = derive(k)?.to_x_only_pub();

                let tree_hash = tree
                    .as_ref()
                    .map(|t| {
                        t.get_taptree_hash(key_information, is_change, address_index)
                            .map(|t| TapNodeHash::from_byte_array(t))
                            .map_err(|_| Error::InvalidKey)
                    })
                    .transpose()?;

                let taproot_key = internal_key.tap_tweak(&secp, tree_hash).0;

                builder
                    .push_int(1)
                    .push_slice(taproot_key.to_x_only_public_key().serialize())
            }
            DescriptorTemplate::Zero => builder.push_opcode(OP_0),
            DescriptorTemplate::One => builder.push_opcode(OP_PUSHNUM_1),
            DescriptorTemplate::Pk(k) => {
                // c:pk_k(key)
                let desc = DescriptorTemplate::C(Box::new(DescriptorTemplate::Pk_k(k.clone())));
                desc.to_script_inner(key_information, is_change, address_index, builder, ctx)?
            }
            DescriptorTemplate::Pk_k(kp) => {
                let key = derive(kp)?;
                if ctx == ScriptContext::Tr {
                    builder.push_slice(key.to_x_only_pub().serialize())
                } else {
                    builder.push_slice(key.to_pub().to_bytes())
                }
            }
            DescriptorTemplate::Pk_h(kp) => {
                let key = derive(kp)?;
                let rip = if ctx == ScriptContext::Tr {
                    hash160::Hash::hash(&key.to_x_only_pub().serialize())
                } else {
                    hash160::Hash::hash(&key.to_pub().to_bytes())
                };

                builder
                    .push_opcode(OP_DUP)
                    .push_opcode(OP_HASH160)
                    .push_slice(&rip.to_byte_array())
                    .push_opcode(OP_EQUALVERIFY)
            }
            DescriptorTemplate::Older(n) => builder.push_int(*n as i64).push_opcode(OP_CSV),
            DescriptorTemplate::After(n) => builder.push_int(*n as i64).push_opcode(OP_CLTV),
            DescriptorTemplate::Sha256(h) => builder
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_SHA256)
                .push_slice(h)
                .push_opcode(OP_EQUAL),
            DescriptorTemplate::Hash256(h) => builder
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH256)
                .push_slice(h)
                .push_opcode(OP_EQUAL),
            DescriptorTemplate::Ripemd160(h) => builder
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_RIPEMD160)
                .push_slice(h)
                .push_opcode(OP_EQUAL),
            DescriptorTemplate::Hash160(h) => builder
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(h)
                .push_opcode(OP_EQUAL),
            DescriptorTemplate::Andor(x, y, z) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_NOTIF)
                .push_inner_script(y, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ELSE)
                .push_inner_script(z, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::And_v(x, y) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_inner_script(y, key_information, is_change, address_index, ctx)?,
            DescriptorTemplate::And_b(x, y) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_inner_script(y, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_BOOLAND),
            DescriptorTemplate::And_n(x, y) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_NOTIF)
                .push_opcode(OP_0)
                .push_opcode(OP_ELSE)
                .push_inner_script(y, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::Or_b(x, z) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_inner_script(z, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_BOOLOR),
            DescriptorTemplate::Or_c(x, z) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_NOTIF)
                .push_inner_script(z, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::Or_d(x, z) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_IFDUP)
                .push_opcode(OP_NOTIF)
                .push_inner_script(z, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::Or_i(x, z) => builder
                .push_opcode(OP_IF)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ELSE)
                .push_inner_script(z, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::Thresh(k, scripts) => {
                for (i, x_i) in scripts.iter().enumerate() {
                    builder = builder.push_inner_script(
                        x_i,
                        key_information,
                        is_change,
                        address_index,
                        ctx,
                    )?;
                    if i > 0 {
                        builder = builder.push_opcode(OP_ADD);
                    }
                }

                builder.push_int(*k as i64).push_opcode(OP_EQUAL)
            }

            // wrappers
            DescriptorTemplate::A(x) => builder
                .push_opcode(OP_TOALTSTACK)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_FROMALTSTACK),
            DescriptorTemplate::S(x) => builder.push_opcode(OP_SWAP).push_inner_script(
                x,
                key_information,
                is_change,
                address_index,
                ctx,
            )?,
            DescriptorTemplate::C(x) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_CHECKSIG),
            DescriptorTemplate::T(x) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_PUSHNUM_1),
            DescriptorTemplate::D(x) => builder
                .push_opcode(OP_DUP)
                .push_opcode(OP_IF)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::V(x) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_verify(),
            DescriptorTemplate::J(x) => builder
                .push_opcode(OP_SIZE)
                .push_opcode(OP_0NOTEQUAL)
                .push_opcode(OP_IF)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::N(x) => builder
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_0NOTEQUAL),
            DescriptorTemplate::L(x) => builder
                .push_opcode(OP_IF)
                .push_opcode(OP_0)
                .push_opcode(OP_ELSE)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ENDIF),
            DescriptorTemplate::U(x) => builder
                .push_opcode(OP_IF)
                .push_inner_script(x, key_information, is_change, address_index, ctx)?
                .push_opcode(OP_ELSE)
                .push_opcode(OP_0)
                .push_opcode(OP_ENDIF),
        };

        Ok(builder)
    }
}

impl ToScriptWithKeyInfo for DescriptorTemplate {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<ScriptBuf, Error> {
        let builder = Builder::new();
        Ok(self
            .to_script_inner(key_information, is_change, address_index, builder, ctx)?
            .as_script()
            .into())
    }
}

// ---------------------------------------------------------------------------
// Cursor-based script derivation (arena form).
//
// This mirrors the owned `to_script_inner` above arm-for-arm, but recurses over
// arena `Cursor`s instead of the owned `DescriptorTemplate` tree. It is the path
// used in production (`WalletPolicy::to_script` below); the owned path is kept
// during the migration and exercised by the differential test in this module.
// Both must produce byte-identical scripts.
// ---------------------------------------------------------------------------

/// Resolves a key expression cursor to its derived `Xpub` at the given
/// coordinates (mirrors the `derive` closure in the owned `to_script_inner`).
fn derive_key<A: ArenaRead>(
    kv: KeyView<'_, A>,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<Xpub, Error> {
    let change_step = ChildNumber::from(if is_change { kv.num2() } else { kv.num1() });
    let path = [change_step, ChildNumber::from(address_index)];
    let secp = bitcoin::secp256k1::Secp256k1::new();

    // Resolve the root xpub of the key expression: either a single participant's
    // xpub (plain) or the BIP-388 aggregate of several participants' (musig).
    let root_xpub: Xpub = if let Some(idx) = kv.plain_key_index() {
        key_information
            .get(idx as usize)
            .ok_or(Error::InvalidKeyIndex)?
            .pubkey
    } else if let Some(indices) = kv.musig_key_indices() {
        let participant_xpubs: Vec<Xpub> = indices
            .iter()
            .map(|&i| {
                key_information
                    .get(i as usize)
                    .map(|ki| ki.pubkey)
                    .ok_or(Error::InvalidKeyIndex)
            })
            .collect::<Result<_, _>>()?;
        crate::musig::aggregate_xpub(&participant_xpubs).map_err(|_| Error::InvalidKey)?
    } else {
        return Err(Error::UnsupportedWalletPolicy);
    };

    root_xpub
        .derive_pub(&secp, &path)
        .map_err(|_| Error::InvalidKey)
}

/// `pk_k(key)`: push the (x-only in taproot) serialized public key.
fn push_pk_k<A: ArenaRead>(
    builder: Builder,
    kv: KeyView<'_, A>,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
    ctx: ScriptContext,
) -> Result<Builder, Error> {
    let key = derive_key(kv, key_information, is_change, address_index)?;
    Ok(if ctx == ScriptContext::Tr {
        builder.push_slice(key.to_x_only_pub().serialize())
    } else {
        builder.push_slice(key.to_pub().to_bytes())
    })
}

/// `multi`/`sortedmulti` (legacy/segwit-v0 `OP_CHECKMULTISIG`).
fn push_multi<A: ArenaRead>(
    mut builder: Builder,
    k: u32,
    keys: KeyListView<'_, A>,
    sorted: bool,
    ctx: ScriptContext,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<Builder, Error> {
    if ctx == ScriptContext::Tr {
        return Err(Error::InvalidScriptContext);
    }
    if keys.len() > MAX_PUBKEYS_PER_MULTISIG {
        return Err(Error::TooManyKeys);
    }
    if k == 0 || (k as usize) > keys.len() {
        return Err(Error::InvalidMultisigQuorum);
    }

    builder = builder.push_int(k as i64);

    let mut derived = keys
        .iter()
        .map(|kv| {
            derive_key(kv, key_information, is_change, address_index)
                .map(|extended_pub_key| extended_pub_key.to_pub().to_bytes())
        })
        .collect::<Result<Vec<[u8; 33]>, Error>>()?;

    if sorted {
        // O(n^2) sorting, better for small arrays
        derived.bubble_sort();
    }

    for key in derived {
        builder = builder.push_slice(&key);
    }

    Ok(builder
        .push_int(keys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG))
}

/// `multi_a`/`sortedmulti_a` (taproot `OP_CHECKSIGADD`).
fn push_multi_a<A: ArenaRead>(
    mut builder: Builder,
    k: u32,
    keys: KeyListView<'_, A>,
    sorted: bool,
    ctx: ScriptContext,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
) -> Result<Builder, Error> {
    if ctx != ScriptContext::Tr {
        return Err(Error::InvalidScriptContext);
    }
    if keys.len() > MAX_PUBKEYS_PER_MULTI_A {
        return Err(Error::TooManyKeys);
    }
    if k == 0 || (k as usize) > keys.len() {
        return Err(Error::InvalidMultisigQuorum);
    }

    let mut derived = keys
        .iter()
        .map(|kv| {
            derive_key(kv, key_information, is_change, address_index).map(|extended_pub_key| {
                extended_pub_key.public_key.x_only_public_key().0.serialize()
            })
        })
        .collect::<Result<Vec<[u8; 32]>, Error>>()?;

    if sorted {
        // O(n^2) sorting, better for small arrays
        derived.bubble_sort();
    }

    for (idx, key) in derived.iter().enumerate() {
        builder = builder.push_slice(key);

        if idx == 0 {
            builder = builder.push_opcode(OP_CHECKSIG);
        } else {
            builder = builder.push_opcode(OP_CHECKSIGADD);
        }
    }

    Ok(builder.push_int(k as i64).push_opcode(OP_NUMEQUAL))
}

/// Builder-chaining helper mirroring `CanPushInnerScript` for arena cursors.
trait CanPushCursorScript {
    fn push_cursor<A: ArenaRead>(
        self,
        c: Cursor<'_, A>,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, Error>;
}

impl CanPushCursorScript for Builder {
    fn push_cursor<A: ArenaRead>(
        self,
        c: Cursor<'_, A>,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, Error> {
        cursor_to_script_inner(c, key_information, is_change, address_index, self, ctx)
    }
}

fn cursor_to_script_inner<A: ArenaRead>(
    cursor: Cursor<'_, A>,
    key_information: &[KeyInformation],
    is_change: bool,
    address_index: u32,
    mut builder: Builder,
    ctx: ScriptContext,
) -> Result<Builder, Error> {
    use DescriptorNode as DN;

    builder = match cursor.view() {
        DN::Sh(inner) => {
            if ctx != ScriptContext::None && ctx != ScriptContext::Wsh {
                return Err(Error::InvalidScriptContext);
            }

            let inner_builder = cursor_to_script_inner(
                inner,
                key_information,
                is_change,
                address_index,
                Builder::new(),
                ScriptContext::Sh,
            )?;

            let script_hash =
                ScriptHash::from_raw_hash(hash160::Hash::hash(&inner_builder.as_bytes()));

            builder
                .push_opcode(OP_HASH160)
                .push_slice(script_hash)
                .push_opcode(OP_EQUAL)
        }
        DN::Wsh(inner) => {
            if ctx != ScriptContext::None {
                return Err(Error::InvalidScriptContext);
            }

            let inner_builder = cursor_to_script_inner(
                inner,
                key_information,
                is_change,
                address_index,
                Builder::new(),
                ScriptContext::Wsh,
            )?;
            let script_hash =
                WScriptHash::from_raw_hash(sha256::Hash::hash(&inner_builder.as_bytes()));
            builder.push_int(0).push_slice(script_hash)
        }
        DN::Pkh(kv) => {
            let key = derive_key(kv, key_information, is_change, address_index)?;
            let pubkey: Vec<u8> = if ctx == ScriptContext::Tr {
                key.to_x_only_pub().serialize().to_vec()
            } else {
                key.to_pub().to_bytes().to_vec()
            };

            let pubkey_hash = PubkeyHash::from_raw_hash(hash160::Hash::hash(&pubkey));

            builder
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(pubkey_hash)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_CHECKSIG)
        }
        DN::Wpkh(kv) => {
            if ctx != ScriptContext::None && ctx != ScriptContext::Sh {
                return Err(Error::InvalidScriptContext);
            }

            let pubkey = derive_key(kv, key_information, is_change, address_index)?
                .public_key
                .serialize();
            let pubkey_hash = WPubkeyHash::from_raw_hash(hash160::Hash::hash(&pubkey));
            builder.push_int(0).push_slice(pubkey_hash)
        }
        DN::Multi(k, keys) => push_multi(
            builder,
            k,
            keys,
            false,
            ctx,
            key_information,
            is_change,
            address_index,
        )?,
        DN::Sortedmulti(k, keys) => push_multi(
            builder,
            k,
            keys,
            true,
            ctx,
            key_information,
            is_change,
            address_index,
        )?,
        DN::MultiA(k, keys) => push_multi_a(
            builder,
            k,
            keys,
            false,
            ctx,
            key_information,
            is_change,
            address_index,
        )?,
        DN::SortedmultiA(k, keys) => push_multi_a(
            builder,
            k,
            keys,
            true,
            ctx,
            key_information,
            is_change,
            address_index,
        )?,
        DN::Tr(kv, tree) => {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let internal_key: UntweakedPublicKey =
                derive_key(kv, key_information, is_change, address_index)?.to_x_only_pub();

            let tree_hash = tree
                .map(|t| {
                    t.get_taptree_hash(key_information, is_change, address_index)
                        .map(TapNodeHash::from_byte_array)
                        .map_err(|_| Error::InvalidKey)
                })
                .transpose()?;

            let taproot_key = internal_key.tap_tweak(&secp, tree_hash).0;

            builder
                .push_int(1)
                .push_slice(taproot_key.to_x_only_public_key().serialize())
        }
        DN::Zero => builder.push_opcode(OP_0),
        DN::One => builder.push_opcode(OP_PUSHNUM_1),
        DN::Pk(kv) => {
            // c:pk_k(key)
            push_pk_k(
                builder,
                kv,
                key_information,
                is_change,
                address_index,
                ctx,
            )?
            .push_opcode(OP_CHECKSIG)
        }
        DN::PkK(kv) => push_pk_k(
            builder,
            kv,
            key_information,
            is_change,
            address_index,
            ctx,
        )?,
        DN::PkH(kv) => {
            let key = derive_key(kv, key_information, is_change, address_index)?;
            let rip = if ctx == ScriptContext::Tr {
                hash160::Hash::hash(&key.to_x_only_pub().serialize())
            } else {
                hash160::Hash::hash(&key.to_pub().to_bytes())
            };

            builder
                .push_opcode(OP_DUP)
                .push_opcode(OP_HASH160)
                .push_slice(rip.to_byte_array())
                .push_opcode(OP_EQUALVERIFY)
        }
        DN::Older(n) => builder.push_int(n as i64).push_opcode(OP_CSV),
        DN::After(n) => builder.push_int(n as i64).push_opcode(OP_CLTV),
        DN::Sha256(h) => builder
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_slice(<&[u8; 32]>::try_from(h).expect("sha256 fragment is 32 bytes"))
            .push_opcode(OP_EQUAL),
        DN::Hash256(h) => builder
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_HASH256)
            .push_slice(<&[u8; 32]>::try_from(h).expect("hash256 fragment is 32 bytes"))
            .push_opcode(OP_EQUAL),
        DN::Ripemd160(h) => builder
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_RIPEMD160)
            .push_slice(<&[u8; 20]>::try_from(h).expect("ripemd160 fragment is 20 bytes"))
            .push_opcode(OP_EQUAL),
        DN::Hash160(h) => builder
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_HASH160)
            .push_slice(<&[u8; 20]>::try_from(h).expect("hash160 fragment is 20 bytes"))
            .push_opcode(OP_EQUAL),
        DN::Andor(x, y, z) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_NOTIF)
            .push_cursor(y, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ELSE)
            .push_cursor(z, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::AndV(x, y) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_cursor(y, key_information, is_change, address_index, ctx)?,
        DN::AndB(x, y) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_cursor(y, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_BOOLAND),
        DN::AndN(x, y) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_0)
            .push_opcode(OP_ELSE)
            .push_cursor(y, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::OrB(x, z) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_cursor(z, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_BOOLOR),
        DN::OrC(x, z) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_NOTIF)
            .push_cursor(z, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::OrD(x, z) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_IFDUP)
            .push_opcode(OP_NOTIF)
            .push_cursor(z, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::OrI(x, z) => builder
            .push_opcode(OP_IF)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ELSE)
            .push_cursor(z, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::Thresh(k, scripts) => {
            for (i, x_i) in scripts.iter().enumerate() {
                builder =
                    builder.push_cursor(x_i, key_information, is_change, address_index, ctx)?;
                if i > 0 {
                    builder = builder.push_opcode(OP_ADD);
                }
            }

            builder.push_int(k as i64).push_opcode(OP_EQUAL)
        }

        // wrappers
        DN::A(x) => builder
            .push_opcode(OP_TOALTSTACK)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_FROMALTSTACK),
        DN::S(x) => builder
            .push_opcode(OP_SWAP)
            .push_cursor(x, key_information, is_change, address_index, ctx)?,
        DN::C(x) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_CHECKSIG),
        DN::T(x) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_PUSHNUM_1),
        DN::D(x) => builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_IF)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::V(x) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_verify(),
        DN::J(x) => builder
            .push_opcode(OP_SIZE)
            .push_opcode(OP_0NOTEQUAL)
            .push_opcode(OP_IF)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::N(x) => builder
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_0NOTEQUAL),
        DN::L(x) => builder
            .push_opcode(OP_IF)
            .push_opcode(OP_0)
            .push_opcode(OP_ELSE)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ENDIF),
        DN::U(x) => builder
            .push_opcode(OP_IF)
            .push_cursor(x, key_information, is_change, address_index, ctx)?
            .push_opcode(OP_ELSE)
            .push_opcode(OP_0)
            .push_opcode(OP_ENDIF),
        DN::TapNode(_) => unreachable!("tap-tree node reached in script context"),
    };

    Ok(builder)
}

impl<'a, A: ArenaRead> ToScriptWithKeyInfo for Cursor<'a, A> {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<ScriptBuf, Error> {
        let builder = Builder::new();
        Ok(
            cursor_to_script_inner(*self, key_information, is_change, address_index, builder, ctx)?
                .as_script()
                .into(),
        )
    }
}

impl ToScript for WalletPolicy {
    fn to_script(&self, is_change: bool, address_index: u32) -> Result<ScriptBuf, Error> {
        self.descriptor_cursor().to_script(
            self.key_information(),
            is_change,
            address_index,
            ScriptContext::None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::WalletPolicy;
    use hex_literal::hex;

    // Four distinct, valid tpubs reused from elsewhere in the test corpus.
    const K0: &str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
    const K1: &str = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm";
    const K2: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";
    const K3: &str = "tpubDD7URPdwnhN6XNWRkMLhaGvhp1xaZNTAqgn8qULdENfMrUbCUcV4Kd4FQzVSHkKx9nmU7sNjBMPa96b9g3KTSJTAvTsTcT5mYDz97fUppvd";

    /// The cursor-based `to_script` (production path) must produce byte-identical
    /// scripts to the owned `DescriptorTemplate::to_script` reference across a
    /// broad corpus of templates and coordinates. This guards the consensus
    /// rewrite of `to_script`/taproot hashing onto arena cursors.
    #[test]
    fn cursor_to_script_matches_owned() {
        let keys = [K0, K1, K2, K3];
        // (template, number of @i keys referenced)
        let corpus: &[(&str, usize)] = &[
            ("pkh(@0/**)", 1),
            ("wpkh(@0/**)", 1),
            ("sh(wpkh(@0/**))", 1),
            ("sh(wsh(multi(2,@0/**,@1/**)))", 2),
            ("wsh(multi(2,@0/**,@1/**,@2/**))", 3),
            ("wsh(sortedmulti(2,@0/**,@1/**))", 2),
            ("sh(sortedmulti(2,@0/**,@1/**))", 2),
            ("sh(wsh(sortedmulti(2,@0/**,@1/**,@2/**)))", 3),
            ("tr(@0/**)", 1),
            ("tr(@0/**,pk(@1/**))", 2),
            ("tr(@0/**,{pk(@1/**),pk(@2/**)})", 3),
            ("tr(@0/**,{pk(@1/**),{pk(@2/**),pk(@3/**)}})", 4),
            ("tr(@0/**,multi_a(2,@1/**,@2/**))", 3),
            ("tr(@0/**,sortedmulti_a(2,@1/**,@2/**))", 3),
            ("wsh(and_v(v:pk(@0/**),older(144)))", 1),
            ("wsh(and_v(v:pk(@0/**),after(1000000)))", 1),
            ("wsh(or_d(pk(@0/**),and_v(v:pk(@1/**),older(65535))))", 2),
            ("wsh(andor(pk(@0/**),older(144),pk(@1/**)))", 2),
            ("wsh(thresh(2,pk(@0/**),s:pk(@1/**),s:pk(@2/**)))", 3),
            ("wsh(or_i(pk(@0/**),pk(@1/**)))", 2),
            (
                "wsh(and_v(v:pk(@0/**),sha256(00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff)))",
                1,
            ),
            (
                "wsh(and_v(v:pk(@0/**),hash160(0011223344556677889900112233445566778899)))",
                1,
            ),
            (
                "wsh(and_v(v:pk(@0/**),hash256(00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff)))",
                1,
            ),
            (
                "wsh(and_v(v:pk(@0/**),ripemd160(0011223344556677889900112233445566778899)))",
                1,
            ),
            ("tr(musig(@0,@1)/**)", 2),
            ("tr(@0/**,pk(musig(@1,@2)/**))", 3),
        ];

        let coords = [(false, 0u32), (false, 5), (true, 0), (true, 99)];

        for (template, n_keys) in corpus {
            let key_info: Vec<_> = keys[..*n_keys]
                .iter()
                .map(|k| (*k).try_into().unwrap())
                .collect();
            let wp = WalletPolicy::new(template, key_info)
                .unwrap_or_else(|e| panic!("failed to parse {template}: {e:?}"));
            // Owned reference AST (oracle), parsed independently of the policy.
            let owned_tmpl: DescriptorTemplate = template
                .parse()
                .unwrap_or_else(|e| panic!("failed to parse owned {template}: {e:?}"));

            for &(is_change, address_index) in &coords {
                // Compare the full Result (success bytes *and* rejection variant)
                // via Debug, so the cursor path matches the owned path on both
                // valid scripts and rejected contexts.
                let owned = owned_tmpl
                    .to_script(
                        wp.key_information(),
                        is_change,
                        address_index,
                        ScriptContext::None,
                    )
                    .map(|s| s.as_bytes().to_vec());
                let cursor = wp
                    .descriptor_cursor()
                    .to_script(
                        wp.key_information(),
                        is_change,
                        address_index,
                        ScriptContext::None,
                    )
                    .map(|s| s.as_bytes().to_vec());
                assert_eq!(
                    format!("{owned:?}"),
                    format!("{cursor:?}"),
                    "script mismatch for {template} @ (is_change={is_change}, index={address_index})"
                );
            }
        }
    }

    /// `tr(musig(@0,@1)/**)` script derivation.
    ///
    /// Cosigner xpubs and expected scriptPubKey are lifted from the C reference
    /// app's `tests/test_musig2.py::test_musig2_hotsigner_keypath` PSBT, whose
    /// input is at (is_change = false, address_index = 3).
    #[test]
    fn tr_musig_keypath_to_script() {
        let cosigner_1_xpub = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
        let cosigner_2_xpub = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm";

        let wallet_policy = WalletPolicy::new(
            "tr(musig(@0,@1)/**)",
            vec![
                cosigner_1_xpub.try_into().unwrap(),
                cosigner_2_xpub.try_into().unwrap(),
            ],
        )
        .unwrap();

        let script = wallet_policy.to_script(false, 3).unwrap();
        // P2TR scriptPubKey from the reference PSBT's witness UTXO.
        let expected =
            hex!("5120c1fdfebed063aa148340c45132e6718d8de81466ae2b90929e3d9328364cd6ed");
        assert_eq!(script.as_bytes(), &expected);
    }

    /// Sanity: changing the (is_change, address_index) tuple produces a
    /// different P2TR scriptPubKey but keeps the P2TR shape.
    #[test]
    fn tr_musig_keypath_changes_with_index() {
        let wallet_policy = WalletPolicy::new(
            "tr(musig(@0,@1)/**)",
            vec![
                "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".try_into().unwrap(),
                "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm".try_into().unwrap(),
            ],
        )
        .unwrap();

        let s_at_3 = wallet_policy.to_script(false, 3).unwrap();
        let s_at_4 = wallet_policy.to_script(false, 4).unwrap();
        let s_change_3 = wallet_policy.to_script(true, 3).unwrap();

        // All are P2TR: 0x51 0x20 <32-byte xonly>
        for s in [&s_at_3, &s_at_4, &s_change_3] {
            assert_eq!(s.len(), 34);
            assert_eq!(s.as_bytes()[0], 0x51);
            assert_eq!(s.as_bytes()[1], 0x20);
        }
        // Indexes and change differ ⇒ different output keys.
        assert_ne!(s_at_3, s_at_4);
        assert_ne!(s_at_3, s_change_3);
    }
}
