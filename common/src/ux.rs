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
    fn serialize(&self, buf: &mut Vec<u8>);
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str>;

    fn serialized(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize(&mut buf);
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

impl Serializable for bool {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(if *self { 1 } else { 0 });
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.push(*self);
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes());
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u16::MAX as usize {
            panic!("string too long");
        }
        (len as u16).serialize(buf);
        buf.extend_from_slice(bytes);
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Some(value) => {
                buf.push(1);
                value.serialize(buf);
            }
            None => {
                buf.push(0);
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        let len = self.len();
        if len > (u32::MAX as usize) {
            panic!("vector too long");
        }
        (len as u32).serialize(buf);
        for item in self {
            item.serialize(buf);
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NavInfo {
    // nbgl_pageNavWithButtons_s
    NavWithButtons {
        has_back_button: bool,
        has_page_indicator: bool,
        quit_text: Option<String>,
    },
}

impl Serializable for NavInfo {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            NavInfo::NavWithButtons {
                has_back_button,
                has_page_indicator,
                quit_text,
            } => {
                buf.push(0x01); // tag for NavWithButtons
                has_back_button.serialize(buf);
                has_page_indicator.serialize(buf);
                quit_text.serialize(buf);
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.is_empty() {
            return Err("slice too short for NavInfo tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0x01 => {
                let (has_back_button, rest) = bool::deserialize(rest)?;
                let (has_page_indicator, rest) = bool::deserialize(rest)?;
                let (quit_text, rest) = Option::<String>::deserialize(rest)?;
                Ok((
                    NavInfo::NavWithButtons {
                        has_back_button,
                        has_page_indicator,
                        quit_text,
                    },
                    rest,
                ))
            }
            _ => Err("unknown NavInfo tag"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NavigationInfo {
    pub active_page: u32,
    pub n_pages: u32,
    pub skip_text: Option<String>,
    pub nav_info: NavInfo,
}

impl Serializable for NavigationInfo {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.active_page.serialize(buf);
        self.n_pages.serialize(buf);
        self.skip_text.serialize(buf);
        self.nav_info.serialize(buf);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (active_page_bytes, rest) = u32::deserialize(slice)?;
        let (n_pages_bytes, rest) = u32::deserialize(rest)?;
        let (skip_text, rest) = Option::<String>::deserialize(rest)?;
        let (nav_info, rest) = NavInfo::deserialize(rest)?;
        Ok((
            NavigationInfo {
                active_page: active_page_bytes,
                n_pages: n_pages_bytes,
                skip_text,
                nav_info,
            },
            rest,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TagValue {
    pub tag: String,
    pub value: String,
}

impl Serializable for TagValue {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.tag.serialize(buf);
        self.value.serialize(buf);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (tag, rest) = String::deserialize(slice)?;
        let (value, rest) = String::deserialize(rest)?;
        Ok((TagValue { tag, value }, rest))
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PageContent {
    TextSubtext {
        // first page of the review pages
        text: String,
        subtext: String,
    },
    TagValueList(Vec<TagValue>),
    ConfirmationButton {
        // as in the useCaseReviewLight
        text: String,
        button_text: String,
    },
    ConfirmationLongPress {
        // as in the useCaseReview
        text: String,
        long_press_text: String,
    },
}

impl Serializable for PageContent {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            PageContent::TextSubtext { text, subtext } => {
                buf.push(0x01);
                text.serialize(buf);
                subtext.serialize(buf);
            }
            PageContent::TagValueList(list) => {
                buf.push(0x02);
                list.serialize(buf);
            }
            PageContent::ConfirmationButton { text, button_text } => {
                buf.push(0x03);
                text.serialize(buf);
                button_text.serialize(buf);
            }
            PageContent::ConfirmationLongPress {
                text,
                long_press_text,
            } => {
                buf.push(0x04); //variant tag
                text.serialize(buf);
                long_press_text.serialize(buf);
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.is_empty() {
            return Err("slice too short for PageContent tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0x01 => {
                let (text, rest) = String::deserialize(rest)?;
                let (subtext, rest) = String::deserialize(rest)?;
                Ok((PageContent::TextSubtext { text, subtext }, rest))
            }
            0x02 => {
                let (list, rest) = Vec::<TagValue>::deserialize(rest)?;
                Ok((PageContent::TagValueList(list), rest))
            }
            0x03 => {
                let (text, rest) = String::deserialize(rest)?;
                let (button_text, rest) = String::deserialize(rest)?;
                Ok((PageContent::ConfirmationButton { text, button_text }, rest))
            }
            0x04 => {
                let (text, rest) = String::deserialize(rest)?;
                let (long_press_text, rest) = String::deserialize(rest)?;
                Ok((
                    PageContent::ConfirmationLongPress {
                        text,
                        long_press_text,
                    },
                    rest,
                ))
            }
            _ => Err("unknown PageContent tag"),
        }
    }
}

// nbgl_pageContent_t
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PageContentInfo {
    pub title: Option<String>,
    pub top_right_icon: Icon,
    pub page_content: PageContent,
}

impl Serializable for PageContentInfo {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        self.title.serialize(buf);
        self.top_right_icon.serialize(buf);
        self.page_content.serialize(buf);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let (title, rest) = Option::<String>::deserialize(slice)?;
        let (top_right_icon, rest) = Icon::deserialize(rest)?;
        let (page_content, rest) = PageContent::deserialize(rest)?;
        Ok((
            PageContentInfo {
                title,
                top_right_icon,
                page_content,
            },
            rest,
        ))
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        let tag: u8 = match self {
            Icon::None => 0,
            Icon::Success => 1,
            Icon::Failure => 2,
        };
        buf.push(tag);
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

/// The various types of pages.
#[derive(Debug, PartialEq)]
pub enum Page {
    /// A page showing a spinner and some text.
    Spinner { text: String },
    /// A page showing an icon (either success or failure) and some text.
    Info { icon: Icon, text: String },
    /// A page with a title, text, a "confirm" button, and a "reject" button.
    ConfirmReject {
        title: String,
        text: String,
        confirm: String,
        reject: String,
    },
    /// A generic page with navigation, implementing a subset of the pages supported by nbgl_pageDrawGenericContent
    GenericPage {
        navigation_info: Option<NavigationInfo>,
        page_content_info: PageContentInfo,
    },
}

impl Serializable for Page {
    #[inline(always)]
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Page::Spinner { text } => {
                buf.push(0x01);
                text.serialize(buf);
            }
            Page::Info { icon, text } => {
                buf.push(0x02);
                icon.serialize(buf);
                text.serialize(buf);
            }
            Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => {
                buf.push(0x03);
                title.serialize(buf);
                text.serialize(buf);
                confirm.serialize(buf);
                reject.serialize(buf);
            }
            Page::GenericPage {
                navigation_info,
                page_content_info,
            } => {
                buf.push(0x04);
                navigation_info.serialize(buf);
                page_content_info.serialize(buf);
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.is_empty() {
            return Err("slice too short for Page tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0x01 => {
                let (text, rest) = String::deserialize(rest)?;
                Ok((Page::Spinner { text }, rest))
            }
            0x02 => {
                let (icon, rest) = Icon::deserialize(rest)?;
                let (text, rest) = String::deserialize(rest)?;
                Ok((Page::Info { icon, text }, rest))
            }
            0x03 => {
                let (title, rest) = String::deserialize(rest)?;
                let (text, rest) = String::deserialize(rest)?;
                let (confirm, rest) = String::deserialize(rest)?;
                let (reject, rest) = String::deserialize(rest)?;
                Ok((
                    Page::ConfirmReject {
                        title,
                        text,
                        confirm,
                        reject,
                    },
                    rest,
                ))
            }
            0x04 => {
                let (navigation_info, rest) = Option::<NavigationInfo>::deserialize(rest)?;
                let (page_content_info, rest) = PageContentInfo::deserialize(rest)?;
                Ok((
                    Page::GenericPage {
                        navigation_info,
                        page_content_info,
                    },
                    rest,
                ))
            }
            _ => Err("unknown Page tag"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_spinner_page() {
        let page = Page::Spinner {
            text: "Loading".to_string(),
        };
        let mut serialized = Vec::new();
        page.serialize(&mut serialized);
        let (deserialized, rest) = Page::deserialize(&serialized).unwrap();
        assert!(rest.is_empty());
        assert_eq!(page, deserialized);
    }
    #[test]
    fn test_icon_page() {
        let page = Page::Info {
            icon: Icon::Failure,
            text: "Error occurred".to_string(),
        };
        let mut serialized = Vec::new();
        page.serialize(&mut serialized);
        let (deserialized, rest) = Page::deserialize(&serialized).unwrap();
        assert!(rest.is_empty());
        assert_eq!(page, deserialized);
    }
    #[test]
    fn test_confirm_reject_page() {
        let page = Page::ConfirmReject {
            title: "Confirm Action".to_string(),
            text: "Are you sure you want to proceed?".to_string(),
            confirm: "Yes".to_string(),
            reject: "No".to_string(),
        };
        let mut serialized = Vec::new();
        page.serialize(&mut serialized);
        let (deserialized, rest) = Page::deserialize(&serialized).unwrap();
        assert!(rest.is_empty());
        assert_eq!(page, deserialized);
    }

    #[test]
    fn test_too_short() {
        // An empty slice should fail.
        let empty: &[u8] = &[];
        assert!(Page::deserialize(empty).is_err());
    }
}
