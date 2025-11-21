use alloc::{string::String, vec::Vec};
use vanadium_macros::Serializable;

use super::codec::*;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    Confirm = 0,
    Reject = 1,
    Quit = 2,
    Skip = 3,
    PreviousPage = 4,
    NextPage = 5,
    TitleBack = 6,
    TopRight = 7,
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

/// For the Icon page, define whether the icon indicates success or failure.
#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(maybe_const))]
pub enum Icon {
    None,
    Success,    // only for flex/stax
    Failure,    // only for flex/stax
    Confirm,    // only for nanos+/nanox
    Reject,     // only for nanos+/nanox
    Processing, // only for nanos+/nanox
}

// Structured types

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedNavInfo))]
pub enum NavInfo {
    #[maker(make_nav_with_buttons)]
    NavWithButtons {
        has_back_button: bool,
        has_page_indicator: bool,
        quit_text: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedNavigationInfo))]
pub struct NavigationInfo {
    pub active_page: u32,
    pub n_pages: u32,
    pub skip_text: Option<String>,
    pub nav_info: NavInfo,
}

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedTagValue))]
pub struct TagValue {
    pub tag: String,
    pub value: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedPageContent))]
pub enum PageContent {
    #[maker(make_text_subtext)]
    TextSubtext { text: String, subtext: String },
    #[maker(make_tag_value_list)]
    TagValueList { list: Vec<TagValue> },
    #[maker(make_confirmation_button)]
    ConfirmationButton { text: String, button_text: String },
    #[maker(make_confirmation_long_press)]
    ConfirmationLongPress {
        text: String,
        long_press_text: String,
    },
}

// nbgl_pageContent_t
#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedPageContentInfo))]
pub struct PageContentInfo {
    pub title: Option<String>,
    pub top_right_icon: Icon,
    pub page_content: PageContent,
}

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedPage))]
pub enum Page {
    /// A page showing a spinner and some text.
    #[maker(make_page_spinner)]
    Spinner { text: String },
    /// A page showing an icon (either success or failure) and some text.
    #[maker(make_page_info)]
    Info { icon: Icon, text: String },
    /// A page with a title, text, a "confirm" button, and a "reject" button.
    #[maker(make_page_confirm_reject)]
    ConfirmReject {
        title: String,
        text: String,
        confirm: String,
        reject: String,
    },
    /// A generic page with navigation, implementing a subset of the pages supported by nbgl_pageDrawGenericContent
    #[maker(make_page_generic_page)]
    GenericPage {
        navigation_info: Option<NavigationInfo>,
        page_content_info: PageContentInfo,
    },
    /// The entry page of a V-App, containing the app description and a 'Quit' button
    #[maker(make_page_home)]
    Home { description: String },
}

// styles for centered info steps
pub const REGULAR_INFO: u8 = 0;
pub const BOLD_TEXT1_INFO: u8 = 1;
pub const BUTTON_INFO: u8 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Serializable)]
#[cfg_attr(feature = "wrapped_serializable", wrapped(name = WrappedStep))]
pub enum Step {
    /// A step showing a spinner and some text.
    #[maker(make_step_text_subtext)]
    TextSubtext {
        pos: u8,
        text: String,
        subtext: String,
        style: u8,
    },
    #[maker(make_step_centered_info)]
    CenteredInfo {
        pos: u8,
        text: Option<String>,
        subtext: Option<String>,
        icon: Icon,
        style: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    // Helper function for round-trip serialization/deserialization tests.
    fn round_trip<T>(value: &T)
    where
        T: Deserializable + Serializable + PartialEq + core::fmt::Debug,
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
    fn test_home_page() {
        let page = Page::Home {
            description: "test".to_string(),
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
