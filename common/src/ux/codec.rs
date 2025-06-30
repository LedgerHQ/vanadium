use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

pub trait Serializable {
    fn get_serialized_length(&self) -> usize;
    fn serialize(&self, buf: &mut [u8], pos: &mut usize);

    #[inline(always)]
    fn serialized(&self) -> Vec<u8> {
        let len = self.get_serialized_length();
        let mut buf = Vec::with_capacity(len);
        // we don't bother initializing the content, since it will be overwritten
        let mut pos = 0;
        self.serialize(&mut buf, &mut pos);
        unsafe {
            buf.set_len(len);
        }
        buf
    }
}

impl<T: Serializable + ?Sized> Serializable for &T {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        T::get_serialized_length(self)
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        T::serialize(self, buf, pos);
    }
}

pub trait Deserializable: Sized {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str>;

    fn deserialize_full(slice: &[u8]) -> Result<Self, &'static str> {
        let (value, rest) = Self::deserialize(slice)?;
        if !rest.is_empty() {
            Err("extra bytes remaining after deserialization")
        } else {
            Ok(value)
        }
    }
}

impl Serializable for bool {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        buf[*pos] = *self as u8;
        *pos += 1;
    }
}

impl Deserializable for bool {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        match slice {
            [0, rest @ ..] => Ok((false, rest)),
            [1, rest @ ..] => Ok((true, rest)),
            [_, ..] => Err("invalid boolean value"),
            _ => Err("slice too short for bool"),
        }
    }
}

impl Serializable for u8 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        buf[*pos] = *self;
        *pos += 1;
    }
}

impl Deserializable for u8 {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        match slice {
            [byte, rest @ ..] => Ok((*byte, rest)),
            _ => Err("slice too short for u8"),
        }
    }
}

impl Serializable for u16 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        2
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        // we avoid using to_be_bytes() and copy_from_slice to make it easier for the compiler to
        // optimize this when serializing a fixed known constant.
        buf[*pos] = (*self >> 8) as u8;
        buf[*pos + 1] = (*self & 0xFF) as u8;
        *pos += 2;
    }
}

impl Deserializable for u16 {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        match slice {
            [b1, b2, rest @ ..] => {
                let value = u16::from_be_bytes([*b1, *b2]);
                Ok((value, rest))
            }
            _ => Err("slice too short for u16"),
        }
    }
}

impl Serializable for u32 {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        // we avoid using to_be_bytes() and copy_from_slice to make it easier for the compiler to
        // optimize this when serializing a fixed known constant.
        buf[*pos] = (*self >> 24) as u8;
        buf[*pos + 1] = ((*self >> 16) & 0xFF) as u8;
        buf[*pos + 2] = ((*self >> 8) & 0xFF) as u8;
        buf[*pos + 3] = (*self & 0xFF) as u8;
        *pos += 4;
    }
}

impl Deserializable for u32 {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        match slice {
            [b1, b2, b3, b4, rest @ ..] => {
                let value = u32::from_be_bytes([*b1, *b2, *b3, *b4]);
                Ok((value, rest))
            }
            _ => Err("slice too short for u32"),
        }
    }
}

impl Serializable for String {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        Serializable::get_serialized_length(self.as_str())
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        Serializable::serialize(self.as_str(), buf, pos);
    }
}

impl Deserializable for String {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (len, rest) = u16::deserialize(slice)?;
        let len = len as usize;
        if rest.len() < len {
            return Err("slice too short for string");
        }
        let (string_bytes, rest) = rest.split_at(len);
        let s = String::from_utf8(string_bytes.to_vec()).map_err(|_| "invalid utf8")?;
        Ok((s, rest))
    }
}

impl<T: Serializable> Serializable for Option<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1 + match self {
            Some(value) => value.get_serialized_length(),
            None => 0,
        }
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        match self {
            Some(value) => {
                buf[*pos] = 1;
                *pos += 1;
                value.serialize(buf, pos);
            }
            None => {
                buf[*pos] = 0;
                *pos += 1;
            }
        }
    }
}

impl<T: Deserializable> Deserializable for Option<T> {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        match slice {
            [0, rest @ ..] => Ok((None, rest)),
            [1, rest @ ..] => {
                let (value, rest) = T::deserialize(rest)?;
                Ok((Some(value), rest))
            }
            [] => Err("slice too short for Option tag"),
            _ => Err("invalid Option tag"),
        }
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        Serializable::get_serialized_length(self.as_slice())
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        Serializable::serialize(self.as_slice(), buf, pos);
    }
}

impl<T: Deserializable> Deserializable for Vec<T> {
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (len, mut rem) = u32::deserialize(slice)?;
        let mut vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let (item, next) = T::deserialize(rem)?;
            vec.push(item);
            rem = next;
        }
        Ok((vec, rem))
    }
}

impl Serializable for str {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        core::mem::size_of::<u16>() + self.len()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let bytes = self.as_bytes();
        let len = self.len();
        let Ok(casted_len) = TryInto::<u16>::try_into(len) else {
            panic!("slice too long");
        };
        Serializable::serialize(&casted_len, buf, pos);
        buf[*pos..][..len].copy_from_slice(bytes);
        *pos += len;
    }
}

impl<T: Serializable> Serializable for [T] {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(Serializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let Ok(len) = TryInto::<u32>::try_into(self.len()) else {
            panic!("slice too long");
        };
        Serializable::serialize(&len, buf, pos);
        for item in self.iter() {
            item.serialize(buf, pos);
        }
    }
}

/// Wrapped Serialization
///
/// This module extends the basic serialization functionality by introducing the concept
/// of wrapped serialization. It allows a type to be serialized as a sequence of parts, where
/// each part can either be a static byte sequence (known at compile-time) or a runtime placeholder
/// (to be resolved later).
///
/// The main components for wrapped serialization are:
///
/// - `MaybeConst<T>` and `MaybeConstStr`:
///   - These enums distinguish between a constant serialized value (the `Const` variant)
///     and a value that is to be provided at runtime (the `Runtime` variant).
///
/// - `SerializedPart`:
///   - This enum represents a part of the wrapped serialization output. It holds either a
///     static vector of bytes (`Static` variant) or a runtime placeholder with associated
///     argument details (`Runtime` variant).
///
/// - `WrappedSerializable` trait:
///   - Types that implement this trait provide a method `serialize_wrapped` which returns
///     a vector of `SerializedPart` instances. This allows complex types to have their serialization
///     split into multiple parts, mixing static and runtime-defined segments.
///
/// - `Wrappable` trait:
///   - This trait defines an association between a type and its wrapped counterpart. It is used
///     to automatically generate wrapped versions of serializable types (e.g., for structs or enums)
///     when the feature flag `wrapped_serializable` is enabled.
///
/// Wrapped serialization is used in the build.rs script of the app-sdk to create efficient serializers
/// for the various types of Page objects.

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MaybeConst<T> {
    Const(T),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Serializable> WrappedSerializable for MaybeConst<T> {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        match self {
            MaybeConst::Const(value) => {
                let mut buf = alloc::vec![0; value.get_serialized_length()];
                let mut pos = 0;
                value.serialize(&mut buf, &mut pos);
                alloc::vec![SerializedPart::Static(buf)]
            }
            MaybeConst::Runtime { arg_name, arg_type } => {
                alloc::vec![SerializedPart::Runtime { arg_name, arg_type }]
            }
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MaybeConstStr {
    Const(&'static str),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
impl WrappedSerializable for MaybeConstStr {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        match self {
            MaybeConstStr::Const(value) => {
                let mut buf = (value.len() as u16).serialized();
                buf.extend_from_slice(value.as_bytes());
                alloc::vec![SerializedPart::Static(buf)]
            }
            MaybeConstStr::Runtime { arg_name, arg_type } => {
                alloc::vec![SerializedPart::Runtime { arg_name, arg_type }]
            }
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
impl<T: WrappedSerializable> WrappedSerializable for Option<T> {
    fn serialize_wrapped(&self) -> Vec<SerializedPart> {
        let mut result = Vec::new();
        match self {
            Some(value) => {
                result.push(SerializedPart::Static(alloc::vec![1]));
                result.extend(value.serialize_wrapped());
            }
            None => {
                result.push(SerializedPart::Static(alloc::vec![0]));
            }
        }
        result
    }
}

#[cfg(feature = "wrapped_serializable")]
pub const fn ct<T: Deserializable>(value: T) -> MaybeConst<T> {
    MaybeConst::Const(value)
}

#[cfg(feature = "wrapped_serializable")]
pub const fn rt<T: Deserializable>(
    arg_name: &'static str,
    arg_type: &'static str,
) -> MaybeConst<T> {
    MaybeConst::Runtime { arg_name, arg_type }
}

#[cfg(feature = "wrapped_serializable")]
pub const fn ct_str(value: &'static str) -> MaybeConstStr {
    MaybeConstStr::Const(value)
}

#[cfg(feature = "wrapped_serializable")]
pub const fn rt_str(arg_name: &'static str, arg_type: &'static str) -> MaybeConstStr {
    MaybeConstStr::Runtime { arg_name, arg_type }
}

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SerializedPart {
    Static(Vec<u8>),
    Runtime {
        arg_name: &'static str,
        arg_type: &'static str,
    },
}

#[cfg(feature = "wrapped_serializable")]
pub trait WrappedSerializable {
    fn serialize_wrapped(&self) -> Vec<SerializedPart>;
}

// This allows to associate what is the wrapped type for a given type.
#[cfg(feature = "wrapped_serializable")]
pub trait Wrappable {
    type Wrapped;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for bool {
    type Wrapped = MaybeConst<bool>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u8 {
    type Wrapped = MaybeConst<u8>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u16 {
    type Wrapped = MaybeConst<u16>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for u32 {
    type Wrapped = MaybeConst<u32>;
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Wrappable> Wrappable for Option<T> {
    type Wrapped = Option<T::Wrapped>;
}

#[cfg(feature = "wrapped_serializable")]
impl<T: Deserializable> Wrappable for Vec<T> {
    // for vectors, we can't really wrap individual elements,
    // as the length of the vector is not statically known
    type Wrapped = MaybeConst<Vec<T>>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for String {
    type Wrapped = MaybeConstStr;
}

// The makeable trait allows to specify the type of argument that should be passed
// to the maker function. This is allows to have (for example) a maker function that
// accepts a `&str` argument, when actual field in the object is a `String`.
pub trait Makeable<'a> {
    type ArgType;
}

impl Makeable<'_> for bool {
    type ArgType = bool;
}

impl Makeable<'_> for u8 {
    type ArgType = u8;
}

impl Makeable<'_> for u16 {
    type ArgType = u16;
}

impl Makeable<'_> for u32 {
    type ArgType = u32;
}

impl<'a, T: Makeable<'a> + 'a> Makeable<'a> for Vec<T> {
    type ArgType = &'a [T];
}

impl<'a> Makeable<'a> for String {
    type ArgType = &'a str;
}

impl<'a, T: Makeable<'a>> Makeable<'a> for Option<T> {
    type ArgType = Option<T::ArgType>;
}
