use alloc::{boxed::Box, vec, vec::Vec};

use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::opcodes::{all::*, OP_0};
use bitcoin::script::Builder;
use bitcoin::{PubkeyHash, ScriptBuf, ScriptHash, TapNodeHash, WPubkeyHash, WScriptHash};

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

use crate::account::{DescriptorTemplate, KeyInformation, KeyPlaceholder, WalletPolicy};

const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const MAX_PUBKEYS_PER_MULTI_A: usize = 999;

pub trait ToScript {
    fn to_script(&self, is_change: bool, address_index: u32) -> Result<ScriptBuf, &'static str>;
}

pub trait ToScriptWithKeyInfo {
    fn to_script(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<ScriptBuf, &'static str>;
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
    ) -> Result<Builder, &'static str>;
}

trait CanPushInnerScript {
    fn push_inner_script(
        self,
        desc: &DescriptorTemplate,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, &'static str>;
}

impl CanPushInnerScript for Builder {
    fn push_inner_script(
        self,
        desc: &DescriptorTemplate,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
        ctx: ScriptContext,
    ) -> Result<Builder, &'static str> {
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
    ) -> Result<Builder, &'static str> {
        let derive = |kp: &KeyPlaceholder| -> Result<Xpub, &'static str> {
            let change_step = ChildNumber::from(if is_change { kp.num2 } else { kp.num1 });

            let key_info = key_information
                .get(kp.key_index as usize)
                .ok_or("Invalid key index")?;

            let root_pubkey = &key_info.pubkey;

            let secp = bitcoin::secp256k1::Secp256k1::new();
            root_pubkey
                .derive_pub(&secp, &vec![change_step, ChildNumber::from(address_index)])
                .map_err(|_| "Failed to produce derived key")
        };

        builder = match self {
            DescriptorTemplate::Sh(inner) => {
                if ctx != ScriptContext::None && ctx != ScriptContext::Wsh {
                    return Err("sh can only be used top-level or inside wsh");
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
                    return Err("wsh can only be used top-level");
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
                    return Err("wpkh can only be used top-level or inside sh");
                }

                let pubkey = derive(kp)?.public_key.serialize();
                let pubkey_hash = WPubkeyHash::from_raw_hash(hash160::Hash::hash(&pubkey));
                builder.push_int(0).push_slice(pubkey_hash)
            }
            DescriptorTemplate::Sortedmulti(k, kps) | DescriptorTemplate::Multi(k, kps) => {
                if ctx == ScriptContext::Tr {
                    return Err("multi and sortedmulti are not valid on taproot");
                }

                if kps.len() > MAX_PUBKEYS_PER_MULTISIG {
                    return Err("Too many keys for multisig");
                }
                if *k == 0 || (*k as usize) > kps.len() {
                    return Err("Invalig multisig quorum");
                }

                builder = builder.push_int(*k as i64);

                let mut keys = kps
                    .iter()
                    .map(|kp| derive(kp))
                    .map(|derived_key_result| {
                        derived_key_result
                            .map(|extended_pub_key| extended_pub_key.to_pub().to_bytes())
                    })
                    .collect::<Result<Vec<[u8; 33]>, &'static str>>()?;

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
                    return Err("multi_a and sortedmulti_a are only valid on taproot");
                }

                if kps.len() > MAX_PUBKEYS_PER_MULTI_A {
                    return Err("Too many keys for multisig");
                }
                if *k == 0 || (*k as usize) > kps.len() {
                    return Err("Invalig multisig quorum");
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
                    .collect::<Result<Vec<[u8; 32]>, &'static str>>()?;

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
                            .map_err(|_| "Failed to compute taptree hash")
                    })
                    .transpose()?;

                let taproot_key = internal_key.tap_tweak(&secp, tree_hash).0;

                builder
                    .push_int(1)
                    .push_slice(taproot_key.to_inner().serialize())
            }
            DescriptorTemplate::Zero => builder.push_opcode(OP_0),
            DescriptorTemplate::One => builder.push_opcode(OP_PUSHNUM_1),
            DescriptorTemplate::Pk(k) => {
                // c:pk_k(key)
                let desc = DescriptorTemplate::C(Box::new(DescriptorTemplate::Pk_k(*k)));
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
    ) -> Result<ScriptBuf, &'static str> {
        let builder = Builder::new();
        Ok(self
            .to_script_inner(key_information, is_change, address_index, builder, ctx)?
            .as_script()
            .into())
    }
}

impl ToScript for WalletPolicy {
    fn to_script(&self, is_change: bool, address_index: u32) -> Result<ScriptBuf, &'static str> {
        self.descriptor_template.to_script(
            &self.key_information,
            is_change,
            address_index,
            ScriptContext::None,
        )
    }
}
