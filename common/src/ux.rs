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
    Title = 6,
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
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            NavInfo::NavWithButtons {
                has_back_button,
                has_page_indicator,
                quit_text,
            } => {
                buf.push(0x01); // tag for NavWithButtons
                buf.push(if *has_back_button { 1 } else { 0 });
                buf.push(if *has_page_indicator { 1 } else { 0 });
                match quit_text {
                    Some(text) => {
                        buf.push(1);
                        write_string(text, buf);
                    }
                    None => {
                        buf.push(0);
                    }
                }
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
                if rest.len() < 3 {
                    return Err("slice too short for NavWithButtons");
                }
                let (back_flag, rest) = rest.split_first().unwrap();
                let (page_flag, rest) = rest.split_first().unwrap();
                let (quit_flag, rest) = rest.split_first().unwrap();
                let has_back_button = *back_flag != 0;
                let has_page_indicator = *page_flag != 0;
                if *quit_flag == 1 {
                    let (quit_text, rest) = read_string(rest)?;
                    Ok((
                        NavInfo::NavWithButtons {
                            has_back_button,
                            has_page_indicator,
                            quit_text: Some(quit_text),
                        },
                        rest,
                    ))
                } else {
                    Ok((
                        NavInfo::NavWithButtons {
                            has_back_button,
                            has_page_indicator,
                            quit_text: None,
                        },
                        rest,
                    ))
                }
            }
            _ => Err("unknown NavInfo tag"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NavigationInfo {
    pub active_page: usize,
    pub n_pages: usize,
    pub skip_text: Option<String>,
    pub nav_info: NavInfo,
}

impl Serializable for NavigationInfo {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize active_page and n_pages as u32 little-endian
        buf.extend_from_slice(&(self.active_page as u32).to_le_bytes());
        buf.extend_from_slice(&(self.n_pages as u32).to_le_bytes());
        // Serialize skip_text with a flag: 1 if Some, 0 if None.
        match &self.skip_text {
            Some(text) => {
                buf.push(1);
                write_string(text, buf);
            }
            None => buf.push(0),
        }
        // Serialize nav_info using its implementation.
        self.nav_info.serialize(buf);
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        // Check for active_page and n_pages (each 4 bytes).
        if slice.len() < 8 {
            return Err("slice too short for NavigationInfo numeric fields");
        }
        let (active_page_bytes, rest) = slice.split_at(4);
        let active_page = u32::from_le_bytes(active_page_bytes.try_into().unwrap()) as usize;
        let (n_pages_bytes, rest) = rest.split_at(4);
        let n_pages = u32::from_le_bytes(n_pages_bytes.try_into().unwrap()) as usize;

        // Check for the skip_text flag.
        if rest.is_empty() {
            return Err("slice too short for NavigationInfo skip_text flag");
        }
        let (flag, rest) = rest.split_first().unwrap();
        let (skip_text, rest) = if *flag == 1 {
            let (text, rest) = read_string(rest)?;
            (Some(text), rest)
        } else {
            (None, rest)
        };

        // Deserialize nav_info.
        let (nav_info, rest) = NavInfo::deserialize(rest)?;
        Ok((
            NavigationInfo {
                active_page,
                n_pages,
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PageContent {
    TagValueList(Vec<TagValue>),
}

// nbgl_pageContent_t
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PageContentInfo {
    pub title: Option<String>,
    pub is_title_touchable: bool,
    pub top_right_icon: Icon,
    pub page_content: PageContent,
}

impl Serializable for PageContentInfo {
    fn serialize(&self, buf: &mut Vec<u8>) {
        // Serialize title option: 1 indicates Some then string, 0 indicates None.
        match &self.title {
            Some(title) => {
                buf.push(1);
                write_string(title, buf);
            }
            None => buf.push(0),
        }
        // Serialize the boolean field.
        buf.push(if self.is_title_touchable { 1 } else { 0 });
        // Serialize the top right icon.
        self.top_right_icon.serialize(buf);
        // Serialize the page content.
        match &self.page_content {
            PageContent::TagValueList(list) => {
                // variant tag for TagValueList.
                buf.push(0x01);
                // Write the list length as u16.
                let len = list.len() as u16;
                write_u16(len, buf);
                // Write each TagValue's tag and value.
                for tv in list {
                    write_string(&tv.tag, buf);
                    write_string(&tv.value, buf);
                }
            }
        }
    }

    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        let mut rem = slice;
        // Deserialize title option.
        let (title_flag, r) = rem.split_first().ok_or("slice too short for title flag")?;
        rem = r;
        let title = if *title_flag == 1 {
            let (t, r) = read_string(rem)?;
            rem = r;
            Some(t)
        } else {
            None
        };
        // Deserialize is_title_touchable.
        let (touch_flag, r) = rem
            .split_first()
            .ok_or("slice too short for is_title_touchable")?;
        rem = r;
        let is_title_touchable = *touch_flag != 0;
        // Deserialize top_right_icon.
        let (top_right_icon, r) = Icon::deserialize(rem)?;
        rem = r;
        // Deserialize page_content.
        let (content_tag, r) = rem
            .split_first()
            .ok_or("slice too short for PageContent tag")?;
        rem = r;
        let page_content = match content_tag {
            0x01 => {
                // Deserialize TagValueList.
                let (len, r) = read_u16(rem)?;
                rem = r;
                let mut list = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    let (tag, r_new) = read_string(rem)?;
                    rem = r_new;
                    let (value, r_new) = read_string(rem)?;
                    rem = r_new;
                    list.push(TagValue { tag, value });
                }
                PageContent::TagValueList(list)
            }
            _ => return Err("unknown PageContent tag"),
        };
        Ok((
            PageContentInfo {
                title,
                is_title_touchable,
                top_right_icon,
                page_content,
            },
            rem,
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
        navigation_info: NavigationInfo,
        page_content_info: PageContentInfo,
    },
}

impl Serializable for Page {
    /// Serialize the page to a Vec<u8> using the following format:
    ///
    /// - 1 byte: page tag (0x01 for Spinner, 0x02 for Icon, 0x03 for ConfirmReject)
    /// - The rest of the bytes depend on the page type.
    ///   - For Spinner: one string (the text)
    ///   - For Icon: one byte for the icon (0=Success, 1=Failure) then one string (the text)
    ///   - For ConfirmReject: four strings (title, text, confirm, reject)
    fn serialize(&self, buf: &mut Vec<u8>) {
        match self {
            Page::Spinner { text } => {
                buf.push(0x01);
                write_string(text, buf);
            }
            Page::Info { icon, text } => {
                buf.push(0x02);
                icon.serialize(buf);
                write_string(text, buf);
            }
            Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => {
                buf.push(0x03);
                write_string(title, buf);
                write_string(text, buf);
                write_string(confirm, buf);
                write_string(reject, buf);
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

    /// Deserialize a Page from a slice.
    /// Returns an error if the slice is too short or contains extra bytes.
    fn deserialize(slice: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if slice.is_empty() {
            return Err("slice too short for page tag");
        }
        let (tag, rest) = slice.split_first().unwrap();
        match tag {
            0x01 => {
                // Spinner page: expect one string.
                let (text, rest) = read_string(rest)?;
                if !rest.is_empty() {
                    return Err("extra bytes after spinner page");
                }
                Ok((Page::Spinner { text }, rest))
            }
            0x02 => {
                // Icon page: first a single byte for the icon, then one string.
                let (icon, rest) = Icon::deserialize(rest)?;
                let (text, rest) = read_string(rest)?;
                if !rest.is_empty() {
                    return Err("extra bytes after icon page");
                }
                Ok((Page::Info { icon, text }, rest))
            }
            0x03 => {
                // ConfirmReject page: expect four strings.
                let (title, rest) = read_string(rest)?;
                let (text, rest) = read_string(rest)?;
                let (confirm, rest) = read_string(rest)?;
                let (reject, rest) = read_string(rest)?;
                if !rest.is_empty() {
                    return Err("extra bytes after confirm/reject page");
                }
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
                // Generic page: expect a NavigationInfo and a PageContentInfo.
                let (navigation_info, rest) = NavigationInfo::deserialize(rest)?;
                let (page_content_info, rest) = PageContentInfo::deserialize(rest)?;
                Ok((
                    Page::GenericPage {
                        navigation_info,
                        page_content_info,
                    },
                    rest,
                ))
            }
            _ => Err("unknown page tag"),
        }
    }
}

/// Writes a u16 (length) in little-endian into the buffer.
fn write_u16(value: u16, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Writes a string as a u16 length followed by its UTF-8 bytes.
/// Panics if the string is longer than u16::MAX bytes.
fn write_string(s: &str, buf: &mut Vec<u8>) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len > u16::MAX as usize {
        panic!("string too long");
    }
    write_u16(len as u16, buf);
    buf.extend_from_slice(bytes);
}

/// Reads a u16 from the slice (in little-endian order).
/// Returns the u16 and the remaining slice.
fn read_u16(slice: &[u8]) -> Result<(u16, &[u8]), &'static str> {
    if slice.len() < 2 {
        return Err("slice too short for u16");
    }
    let (int_bytes, rest) = slice.split_at(2);
    let arr: [u8; 2] = int_bytes.try_into().unwrap();
    let value = u16::from_le_bytes(arr);
    Ok((value, rest))
}

/// Reads a string that was encoded as a u16 length followed by UTF-8 bytes.
fn read_string(slice: &[u8]) -> Result<(String, &[u8]), &'static str> {
    let (len, slice) = read_u16(slice)?;
    let len = len as usize;
    if slice.len() < len {
        return Err("slice too short for string");
    }
    let (string_bytes, rest) = slice.split_at(len);
    let s = String::from_utf8(string_bytes.to_vec()).map_err(|_| "invalid utf8")?;
    Ok((s, rest))
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
