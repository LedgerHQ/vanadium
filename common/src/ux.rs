use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    Confirm = 0,
    Reject = 1,
    Quit = 2,
    Skip = 3,
    PreviousPage = 4, // TODO: page index is part of the event data
    NextPage = 5,
    TitleBack = 6,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EventCode {
    Ticker = 0,
    Action = 1,
    Unknown = 0xFFFFFFFF,
}

impl From<u32> for EventCode {
    fn from(value: u32) -> Self {
        match value {
            0 => EventCode::Ticker,
            1 => EventCode::Action,
            _ => EventCode::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventData {
    pub ticker: TickerEvent,
    pub action: Action,
    // Reserve space for future expansions. Each event's raw data is exactly 16 bytes.
    // For events that do not define the meaning of the raw data, the value of those bytes is undefined
    // and could change in future versions.
    pub raw: [u8; 16],
}

impl Default for EventData {
    fn default() -> Self {
        EventData { raw: [0; 16] }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TickerEvent {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Event {
    Ticker,
    Action(Action),
    Unknown([u8; 16]),
}

pub trait Serializable: Sized {
    fn get_serialized_length(&self) -> usize;

    fn serialize(&self, buf: &mut [u8], pos: &mut usize);
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str>;

    #[inline(always)]
    fn serialized(&self) -> Vec<u8> {
        let len = self.get_serialized_length();
        let mut buf = Vec::with_capacity(len);
        unsafe {
            // we don't bother initializing the content, since it will be overwritten
            buf.set_len(len);
        }
        let mut pos = 0;
        self.serialize(&mut buf, &mut pos);
        buf
    }

    fn deserialize_full(slice: &[u8]) -> Result<Self, &'static str> {
        let (value, rest) = Self::deserialize(slice)?;
        if !rest.is_empty() {
            Err("extra bytes remaining after deserialization")
        } else {
            Ok(value)
        }
    }
}

#[cfg(feature = "wrapped_serializable")]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MaybeConst<T: Serializable> {
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
pub const fn ct<T: Serializable>(value: T) -> MaybeConst<T> {
    MaybeConst::Const(value)
}

#[cfg(feature = "wrapped_serializable")]
pub const fn rt<T: Serializable>(arg_name: &'static str, arg_type: &'static str) -> MaybeConst<T> {
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
impl<T: Serializable> Wrappable for Vec<T> {
    // for vectors, we can't really wrap individual elements,
    // as the length of the vector is not statically known
    type Wrapped = MaybeConst<Vec<T>>;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for String {
    type Wrapped = MaybeConstStr;
}

#[cfg(feature = "wrapped_serializable")]
impl Wrappable for Icon {
    type Wrapped = MaybeConst<Icon>;
}

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

impl Makeable<'_> for Icon {
    type ArgType = Icon;
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

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&byte, rest)) = slice.split_first() {
            match byte {
                0 => Ok((false, rest)),
                1 => Ok((true, rest)),
                _ => Err("invalid boolean value"),
            }
        } else {
            Err("slice too short for bool")
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

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&byte, rest)) = slice.split_first() {
            Ok((byte, rest))
        } else {
            Err("slice too short for u8")
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

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 2 {
            Err("slice too short for u16")
        } else {
            let (bytes, rest) = slice.split_at(2);
            let arr: [u8; 2] = bytes.try_into().unwrap();
            Ok((u16::from_be_bytes(arr), rest))
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

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 4 {
            Err("slice too short for u32")
        } else {
            let (bytes, rest) = slice.split_at(4);
            let arr: [u8; 4] = bytes.try_into().unwrap();
            Ok((u32::from_be_bytes(arr), rest))
        }
    }
}

impl Serializable for String {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        core::mem::size_of::<u16>() + self.len()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u16::MAX as usize {
            panic!("string too long");
        }
        (len as u16).serialize(buf, pos);

        buf[*pos..*pos + len].copy_from_slice(bytes);
        *pos += len;
    }

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

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if let Some((&tag, rest)) = slice.split_first() {
            match tag {
                1 => {
                    let (value, rest) = T::deserialize(rest)?;
                    Ok((Some(value), rest))
                }
                0 => Ok((None, rest)),
                _ => Err("invalid Option tag"),
            }
        } else {
            Err("slice too short for Option tag")
        }
    }
}

impl<T: Serializable> Serializable for Vec<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(Serializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("vector too long");
        }
        (len as u32).serialize(buf, pos);
        for item in self {
            item.serialize(buf, pos);
        }
    }

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

// a reduced-functionality version of Serializable, only used for &str
// and its composite types, and slices of Serializable types.
pub trait MiniSerializable: Sized {
    fn get_serialized_length(&self) -> usize;
    fn serialize(&self, buf: &mut [u8], pos: &mut usize);
}

impl MiniSerializable for &str {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        core::mem::size_of::<u16>() + self.len()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u16::MAX as usize {
            panic!("string too long");
        }
        (len as u16).serialize(buf, pos);
        buf[*pos..*pos + len].copy_from_slice(bytes);
        *pos += len;
    }
}

impl<T: Serializable> MiniSerializable for &[T] {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(Serializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("slice too long");
        }
        (len as u32).serialize(buf, pos);
        for item in self.iter() {
            item.serialize(buf, pos);
        }
    }
}

impl<T: MiniSerializable> MiniSerializable for Option<T> {
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

impl<T: MiniSerializable> MiniSerializable for Vec<T> {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        4 + self
            .iter()
            .map(MiniSerializable::get_serialized_length)
            .sum::<usize>()
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("vector too long");
        }

        (len as u32).serialize(buf, pos);
        for item in self {
            item.serialize(buf, pos);
        }
    }
}

/// For the Icon page, define whether the icon indicates success or failure.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Icon {
    None,
    Success,
    Failure,
}

impl Serializable for Icon {
    #[inline(always)]
    fn get_serialized_length(&self) -> usize {
        1
    }

    #[inline(always)]
    fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
        let tag: u8 = match self {
            Icon::None => 0,
            Icon::Success => 1,
            Icon::Failure => 2,
        };
        tag.serialize(buf, pos);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.len() < 1 {
            return Err("slice too short for icon tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0 => Ok((Icon::None, rest)),
            1 => Ok((Icon::Success, rest)),
            2 => Ok((Icon::Failure, rest)),
            _ => Err("invalid icon tag"),
        }
    }
}

// MACROS

macro_rules! define_serializable_struct {
    (
        $name:ident {
            $($field:ident : $field_ty:ty),* $(,)?
        },
        wrapped: $wrapped_name:ident
    ) => {
        // Non-wrapped struct
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            $(pub $field: $field_ty),*
        }

        impl Serializable for $name {
            #[inline(always)]
            fn get_serialized_length(&self) -> usize {
                0 $( + self.$field.get_serialized_length() )*
            }

            #[inline(always)]
            fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
                $( self.$field.serialize(buf, pos); )*
            }

            fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                let mut slice = slice;
                $(
                    let ($field, new_slice) = <$field_ty>::deserialize(slice)?;
                    slice = new_slice;
                )*
                Ok((Self { $($field),* }, slice))
            }
        }

        // Wrapped struct (under feature flag)
        #[cfg(feature = "wrapped_serializable")]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $wrapped_name {
            $(pub $field: <$field_ty as Wrappable>::Wrapped),*
        }

        #[cfg(feature = "wrapped_serializable")]
        impl WrappedSerializable for $wrapped_name {
            fn serialize_wrapped(&self) -> Vec<SerializedPart> {
                let mut parts = Vec::new();
                $(
                    parts.extend(self.$field.serialize_wrapped());
                )*
                parts
            }
        }

        #[cfg(feature = "wrapped_serializable")]
        impl Wrappable for $name {
            type Wrapped = $wrapped_name;
        }

        impl Makeable<'_> for $name {
            type ArgType = $name;
        }
    };
}

macro_rules! define_serializable_enum {
    (
        $name:ident {
            $(
                $tag:expr => $variant:ident {
                    $($field:ident : $enum_ty:ty),* $(,)?
                } as ($fn_maker:ident, $fn_maker_wrapped:ident)
            ),* $(,)?
        },
        wrapped: $wrapped_name:ident
    ) => {
        // Non-wrapped enum
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum $name {
            $(
                $variant { $($field: $enum_ty),* },
            )*
        }

        impl Serializable for $name {
            #[inline(always)]
            fn get_serialized_length(&self) -> usize {
                match self {
                    $(
                        Self::$variant { $($field),* } => 1 $( + $field.get_serialized_length() )*
                    ),*
                }
            }

            #[inline(always)]
            fn serialize(&self, buf: &mut [u8], pos: &mut usize) {
                match self {
                    $(
                        Self::$variant { $($field),* } => {
                            $tag.serialize(buf, pos);
                            $(
                                $field.serialize(buf, pos);
                            )*
                        }
                    ),*
                }
            }

            fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
                if slice.is_empty() {
                    return Err(concat!(stringify!($name), " slice too short for tag"));
                }
                let (tag, rest) = slice.split_first().unwrap();
                match tag {
                    $(
                        x if *x == $tag => {
                            let mut r = rest;
                            $(
                                let ($field, new_r) = <$enum_ty>::deserialize(r)?;
                                r = new_r;
                            )*
                            Ok((Self::$variant { $($field),* }, r))
                        }
                    ),*,
                    _ => Err("unknown tag"),
                }
            }
        }

        // Maker functions
        impl $name {
            $(
                #[inline(always)]
                pub fn $fn_maker($($field: <$enum_ty as Makeable>::ArgType),*) -> Vec<u8> {
                    let len = {
                        let mut len = $tag.get_serialized_length();
                        $( len += $field.get_serialized_length(); )*
                        len
                    };
                    let mut buf = Vec::with_capacity(len);
                    unsafe { buf.set_len(len); }
                    let mut pos: usize = 0;
                    $tag.serialize(&mut buf, &mut pos);
                    $( $field.serialize(&mut buf, &mut pos); )*
                    buf
                }
            )*
        }

        // Wrapped enum
        #[cfg(feature = "wrapped_serializable")]
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub enum $wrapped_name {
            $(
                $variant { $($field: <$enum_ty as Wrappable>::Wrapped),* },
            )*
        }

        #[cfg(feature = "wrapped_serializable")]
        impl WrappedSerializable for $wrapped_name {
            fn serialize_wrapped(&self) -> Vec<SerializedPart> {
                let mut parts = Vec::new();
                match self {
                    $(
                        Self::$variant { $($field),* } => {
                            parts.push(SerializedPart::Static(alloc::vec![$tag]));
                            $(
                                parts.extend($field.serialize_wrapped());
                            )*
                        }
                    ),*
                }
                parts
            }
        }

        #[cfg(feature = "wrapped_serializable")]
        impl Wrappable for $name {
            type Wrapped = $wrapped_name;
        }

        impl Makeable<'_> for $name {
            type ArgType = $name;
        }
    };
}

// Structured types

define_serializable_enum! {
    NavInfo {
        0x01u8 => NavWithButtons {
            has_back_button: bool,
            has_page_indicator: bool,
            quit_text: Option<String>,
        } as (make_nav_with_buttons, make_nav_with_buttons_wrapped),
    },
    wrapped: WrappedNavInfo
}

define_serializable_struct! {
    NavigationInfo {
        active_page: u32,
        n_pages: u32,
        skip_text: Option<String>,
        nav_info: NavInfo
    },
    wrapped: WrappedNavigationInfo
}

define_serializable_struct! {
    TagValue {
        tag: String,
        value: String,
    },
    wrapped: WrappedTagValue
}

define_serializable_enum! {
    PageContent {
        0x01u8 => TextSubtext {
            text: String,
            subtext: String,
        } as (make_text_subtext, make_text_subtext_wrapped),
        0x02u8 => TagValueList {
            list: Vec<TagValue>,
        } as (make_tag_value_list, make_tag_value_list_wrapped),
        0x03u8 => ConfirmationButton {
            text: String,
            button_text: String,
        } as (make_confirmation_button, make_confirmation_button_wrapped),
        0x04u8 => ConfirmationLongPress {
            text: String,
            long_press_text: String,
        } as (make_confirmation_long_press, make_confirmation_long_press_wrapped),
    },
    wrapped: WrappedPageContent
}

// nbgl_pageContent_t
define_serializable_struct! {
    PageContentInfo {
        title: Option<String>,
        top_right_icon: Icon,
        page_content: PageContent,
    },
    wrapped: WrappedPageContentInfo
}

define_serializable_enum! {
    Page {
        // A page showing a spinner and some text.
        0x01u8 => Spinner {
            text: String,
        } as (make_spinner, make_spinner_wrapped),
        // A page showing an icon (either success or failure) and some text.
        0x02u8 => Info {
            icon: Icon,
            text: String,
        } as (make_info, make_info_wrapped),
        // A page with a title, text, a "confirm" button, and a "reject" button.
        0x03u8 => ConfirmReject {
            title: String,
            text: String,
            confirm: String,
            reject: String,
        } as (make_confirm_reject, make_confirm_reject_wrapped),
        // A generic page with navigation, implementing a subset of the pages supported by nbgl_pageDrawGenericContent
        0x04u8 => GenericPage {
            navigation_info: Option<NavigationInfo>,
            page_content_info: PageContentInfo }
            as (make_generic_page, make_generic_page_wrapped),
    },
    wrapped: WrappedPage
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    // Helper function for round-trip serialization/deserialization tests.
    fn round_trip<T>(value: &T)
    where
        T: Serializable + PartialEq + core::fmt::Debug,
    {
        let serialized = value.serialized();
        let (deserialized, rest) = T::deserialize(&serialized).unwrap();
        assert!(rest.is_empty(), "There should be no remaining bytes");
        assert_eq!(value, &deserialized);
    }

    #[test]
    fn test_spinner_page() {
        let page = Page::Spinner {
            text: "Loading".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_icon_page() {
        let page = Page::Info {
            icon: Icon::Failure,
            text: "Error occurred".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_confirm_reject_page() {
        let page = Page::ConfirmReject {
            title: "Confirm Action".to_string(),
            text: "Are you sure you want to proceed?".to_string(),
            confirm: "Yes".to_string(),
            reject: "No".to_string(),
        };
        round_trip(&page);
    }

    #[test]
    fn test_generic_page() {
        // Create a NavigationInfo with a NavWithButtons variant.
        let nav_info = NavigationInfo {
            active_page: 2,
            n_pages: 5,
            skip_text: Some("Skip".to_string()),
            nav_info: NavInfo::NavWithButtons {
                has_back_button: true,
                has_page_indicator: false,
                quit_text: Some("Quit".to_string()),
            },
        };
        // Create a PageContentInfo using the TextSubtext variant.
        let page_content_info = PageContentInfo {
            title: Some("Generic Page".to_string()),
            top_right_icon: Icon::Success,
            page_content: PageContent::TextSubtext {
                text: "Welcome".to_string(),
                subtext: "to the generic page".to_string(),
            },
        };
        let page = Page::GenericPage {
            navigation_info: Some(nav_info),
            page_content_info,
        };
        round_trip(&page);
    }

    #[test]
    fn test_page_content_text_subtext() {
        let content = PageContent::TextSubtext {
            text: "Main text".to_string(),
            subtext: "Additional info".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_tag_value_list() {
        let tag_value1 = TagValue {
            tag: "tag1".to_string(),
            value: "value1".to_string(),
        };
        let tag_value2 = TagValue {
            tag: "tag2".to_string(),
            value: "value2".to_string(),
        };
        let content = PageContent::TagValueList {
            list: vec![tag_value1, tag_value2],
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_confirmation_button() {
        let content = PageContent::ConfirmationButton {
            text: "Confirm?".to_string(),
            button_text: "OK".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_page_content_confirmation_long_press() {
        let content = PageContent::ConfirmationLongPress {
            text: "Hold to confirm".to_string(),
            long_press_text: "Long press here".to_string(),
        };
        round_trip(&content);
    }

    #[test]
    fn test_navigation_info() {
        let nav_info = NavigationInfo {
            active_page: 1,
            n_pages: 3,
            skip_text: None,
            nav_info: NavInfo::NavWithButtons {
                has_back_button: false,
                has_page_indicator: true,
                quit_text: None,
            },
        };
        round_trip(&nav_info);
    }

    #[test]
    fn test_deserialize_full_extra_bytes() {
        // Serialize a page and then append an extra byte.
        let page = Page::Spinner {
            text: "Loading".to_string(),
        };
        let mut serialized = page.serialized();
        serialized.push(42); // Append extra data.
        let result = Page::deserialize_full(&serialized);
        assert!(
            result.is_err(),
            "deserialize_full should error if extra bytes remain"
        );
    }

    #[test]
    fn test_invalid_tag() {
        // Serialize a valid page and then change its tag to an invalid value.
        let mut serialized = Page::Spinner {
            text: "Loading".to_string(),
        }
        .serialized();
        serialized[0] = 0xFF; // 0xFF is not a valid tag.
        let result = Page::deserialize(&serialized);
        assert!(result.is_err(), "Invalid tag should result in an error");
    }

    #[test]
    fn test_truncated_data() {
        // Serialize a valid ConfirmReject page and then truncate the data.
        let serialized = Page::ConfirmReject {
            title: "Confirm".to_string(),
            text: "Proceed?".to_string(),
            confirm: "Yes".to_string(),
            reject: "No".to_string(),
        }
        .serialized();
        let truncated = &serialized[..serialized.len() - 2]; // Remove last 2 bytes.
        let result = Page::deserialize(truncated);
        assert!(
            result.is_err(),
            "Truncated data should fail deserialization"
        );
    }

    #[test]
    fn test_too_short() {
        // An empty slice should fail.
        let empty: &[u8] = &[];
        assert!(
            Page::deserialize(empty).is_err(),
            "Empty slice should return an error"
        );
    }
}
