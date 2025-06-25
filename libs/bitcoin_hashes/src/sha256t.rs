// SPDX-License-Identifier: CC0-1.0

//! SHA256t implementation (tagged SHA256).
//!

use core::marker::PhantomData;
use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, str};

use crate::{sha256, FromSliceError};

type HashEngine = sha256::HashEngine;

/// Trait representing a tag that can be used as a context for SHA256t hashes.
pub trait Tag {
    /// Returns a hash engine that is pre-tagged and is ready to be used for the data.
    fn engine() -> sha256::HashEngine;
}

/// Output of the SHA256t hash function.
#[repr(transparent)]
pub struct Hash<T: Tag>([u8; 32], PhantomData<T>);

#[cfg(feature = "schemars")]
impl<T: Tag> schemars::JsonSchema for Hash<T> {
    fn schema_name() -> String { "Hash".to_owned() }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema: schemars::schema::SchemaObject = <String>::json_schema(gen).into();
        schema.string = Some(Box::new(schemars::schema::StringValidation {
            max_length: Some(32 * 2),
            min_length: Some(32 * 2),
            pattern: Some("[0-9a-fA-F]+".to_owned()),
        }));
        schema.into()
    }
}

impl<T: Tag> Hash<T> {
    fn internal_new(arr: [u8; 32]) -> Self { Hash(arr, Default::default()) }

    fn internal_engine() -> HashEngine { T::engine() }
}

impl<T: Tag> Copy for Hash<T> {}
impl<T: Tag> Clone for Hash<T> {
    fn clone(&self) -> Self { *self }
}
impl<T: Tag> PartialEq for Hash<T> {
    fn eq(&self, other: &Hash<T>) -> bool { self.0 == other.0 }
}
impl<T: Tag> Eq for Hash<T> {}
impl<T: Tag> Default for Hash<T> {
    fn default() -> Self { Hash([0; 32], PhantomData) }
}
impl<T: Tag> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Hash<T>) -> Option<cmp::Ordering> {
        Some(cmp::Ord::cmp(self, other))
    }
}
impl<T: Tag> Ord for Hash<T> {
    fn cmp(&self, other: &Hash<T>) -> cmp::Ordering { cmp::Ord::cmp(&self.0, &other.0) }
}
impl<T: Tag> core::hash::Hash for Hash<T> {
    fn hash<H: core::hash::Hasher>(&self, h: &mut H) { self.0.hash(h) }
}

crate::internal_macros::hash_trait_impls!(256, true, T: Tag);

fn from_engine<T: Tag>(e: sha256::HashEngine) -> Hash<T> {
    use crate::Hash as _;

    Hash::from_byte_array(sha256::Hash::from_engine(e).to_byte_array())
}

/// This is a stripped down version of the original macro in bitcoin_hashes, to make the code
/// using tagged hashes still compile after all the API related to midstate was removed.
/// It wraps around the sha256 hash engine, without optimizing the midstate for the tagged hash.
#[macro_export]
macro_rules! sha256t_hash_newtype {
    ($($(#[$($tag_attr:tt)*])* $tag_vis:vis struct $tag:ident = $constructor:tt($tag_value:tt); $(#[$($hash_attr:tt)*])* $hash_vis:vis struct $hash_name:ident($(#[$($field_attr:tt)*])* _);)+) => {
        $(
        $crate::sha256t_hash_newtype_tag!($tag_vis, $tag, stringify!($hash_name), $(#[$($tag_attr)*])*);

        impl $crate::sha256t::Tag for $tag {
            #[inline]
            fn engine() -> $crate::sha256::HashEngine {
                use $crate::HashEngine as _;
                use $crate::Hash as _;
                let mut res = $crate::sha256::HashEngine::default();
                let tag_hash = $crate::sha256::Hash::hash($tag_value.as_bytes());
                res.input(tag_hash.as_byte_array());
                res.input(tag_hash.as_byte_array());
                res
            }
        }

        $crate::hash_newtype! {
            $(#[$($hash_attr)*])*
            $hash_vis struct $hash_name($(#[$($field_attr)*])* $crate::sha256t::Hash<$tag>);
        }
        )+
    }
}

// Workaround macros being unavailable in attributes.
#[doc(hidden)]
#[macro_export]
macro_rules! sha256t_hash_newtype_tag {
    ($vis:vis, $tag:ident, $name:expr, $(#[$($attr:meta)*])*) => {
        #[doc = "The tag used for [`"]
        #[doc = $name]
        #[doc = "`]\n\n"]
        $(#[$($attr)*])*
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        $vis struct $tag;
    };
}
