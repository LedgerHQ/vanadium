use alloc::{string::String, vec::Vec};
use core::convert::TryInto;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    Confirm = 0,
    Reject = 1,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    Ticker,
    Action(Action),
    Unknown([u8; 16]),
}

/// The three types of pages.
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
}

/// For the Icon page, define whether the icon indicates success or failure.
#[derive(Debug, PartialEq)]
pub enum Icon {
    None,
    Success,
    Failure,
}

impl Icon {
    /// Serialize the icon as a single byte: 0 for success, 1 for failure.
    fn serialize(&self, buf: &mut Vec<u8>) {
        let tag: u8 = match self {
            Icon::None => 0,
            Icon::Success => 1,
            Icon::Failure => 2,
        };
        buf.push(tag);
    }

    /// Deserialize an icon from the beginning of `slice`.
    /// Returns the parsed icon and the remaining slice.
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

impl Page {
    /// Serialize the page to a Vec<u8> using the following format:
    ///
    /// - 1 byte: page tag (0x01 for Spinner, 0x02 for Icon, 0x03 for ConfirmReject)
    /// - The rest of the bytes depend on the page type.
    ///   - For Spinner: one string (the text)
    ///   - For Icon: one byte for the icon (0=Success, 1=Failure) then one string (the text)
    ///   - For ConfirmReject: four strings (title, text, confirm, reject)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Page::Spinner { text } => {
                buf.push(0x01);
                write_string(text, &mut buf);
            }
            Page::Info { icon, text } => {
                buf.push(0x02);
                icon.serialize(&mut buf);
                write_string(text, &mut buf);
            }
            Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => {
                buf.push(0x03);
                write_string(title, &mut buf);
                write_string(text, &mut buf);
                write_string(confirm, &mut buf);
                write_string(reject, &mut buf);
            }
        }
        buf
    }

    /// Deserialize a Page from a slice.
    /// Returns an error if the slice is too short or contains extra bytes.
    pub fn deserialize(slice: &[u8]) -> Result<Self, &'static str> {
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
                Ok(Page::Spinner { text })
            }
            0x02 => {
                // Icon page: first a single byte for the icon, then one string.
                let (icon, rest) = Icon::deserialize(rest)?;
                let (text, rest) = read_string(rest)?;
                if !rest.is_empty() {
                    return Err("extra bytes after icon page");
                }
                Ok(Page::Info { icon, text })
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
                Ok(Page::ConfirmReject {
                    title,
                    text,
                    confirm,
                    reject,
                })
            }
            _ => Err("unknown page tag"),
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
        let serialized = page.serialize();
        let deserialized = Page::deserialize(&serialized).unwrap();
        assert_eq!(page, deserialized);
    }

    #[test]
    fn test_icon_page() {
        let page = Page::Info {
            icon: Icon::Failure,
            text: "Error occurred".to_string(),
        };
        let serialized = page.serialize();
        let deserialized = Page::deserialize(&serialized).unwrap();
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
        let serialized = page.serialize();
        let deserialized = Page::deserialize(&serialized).unwrap();
        assert_eq!(page, deserialized);
    }

    #[test]
    fn test_too_short() {
        // An empty slice should fail.
        let empty: &[u8] = &[];
        assert!(Page::deserialize(empty).is_err());
    }
}
