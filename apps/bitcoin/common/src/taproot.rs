// TODO: can we get rid of this module and use the corresponding code from vlib-bitcoin?

use bitcoin::{hashes::Hash, taproot::LeafVersion};
use bitcoin::{TapLeafHash, TapNodeHash};

use crate::{
    account::{DescriptorTemplate, KeyInformation, TapTree},
    errors::Error,
    script::{ScriptContext, ToScriptWithKeyInfo},
};

pub trait GetTapTreeHash {
    fn get_taptree_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], Error>;
}

impl GetTapTreeHash for TapTree {
    fn get_taptree_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<[u8; 32], Error> {
        match self {
            TapTree::Script(leaf_desc) => Ok(leaf_desc
                .get_tapleaf_hash(key_information, is_change, address_index)?
                .as_raw_hash()
                .to_byte_array()),
            TapTree::Branch(l, r) => {
                let l_bytes = l.get_taptree_hash(key_information, is_change, address_index)?;
                let r_bytes = r.get_taptree_hash(key_information, is_change, address_index)?;
                let l_hash = TapNodeHash::from_slice(&l_bytes).map_err(|_| Error::InvalidKey)?;
                let r_hash = TapNodeHash::from_slice(&r_bytes).map_err(|_| Error::InvalidKey)?;

                Ok(TapNodeHash::from_node_hashes(l_hash, r_hash)
                    .as_raw_hash()
                    .to_byte_array())
            }
        }
    }
}

pub trait GetTapLeafHash {
    fn get_tapleaf_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<TapLeafHash, Error>;
}

impl GetTapLeafHash for DescriptorTemplate {
    fn get_tapleaf_hash(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<TapLeafHash, Error> {
        let script =
            self.to_script(key_information, is_change, address_index, ScriptContext::Tr)?;
        Ok(TapLeafHash::from_script(
            script.as_script(),
            LeafVersion::TapScript,
        ))
    }
}
