use crate::ecalls::{Ecall, EcallsInterface};
use alloc::{string::ToString, vec::Vec};

use common::ux::{Action, Serializable};
pub use common::ux::{
    Event, EventCode, EventData, Icon, NavInfo, NavigationInfo, Page, PageContent, PageContentInfo,
    TagValue,
};

/// Blocks until an event is received, then returns it.
pub fn get_event() -> Event {
    loop {
        let mut event_data = EventData::default();
        let event_code = EventCode::from(Ecall::get_event(&mut event_data));
        match event_code {
            EventCode::Ticker => {
                return Event::Ticker;
            }
            EventCode::Action => {
                let action = unsafe { event_data.action };
                // TODO: sanitize?
                return Event::Action(action);
            }
            EventCode::Unknown => {
                let data = unsafe { event_data.raw };
                return Event::Unknown(data);
            }
        }
    }
}

pub fn show_page(page: &Page) {
    let mut serialized_page = Vec::new();
    page.serialize(&mut serialized_page);
    Ecall::show_page(serialized_page.as_ptr(), serialized_page.len());
}

pub fn show_spinner(text: &str) {
    show_page(&Page::Spinner {
        text: text.to_string(),
    });
}

pub fn show_info(icon: Icon, text: &str) {
    show_page(&Page::Info {
        icon,
        text: text.to_string(),
    });
}

pub fn show_confirm_reject(title: &str, text: &str, confirm: &str, reject: &str) -> bool {
    show_page(&Page::ConfirmReject {
        title: title.to_string(),
        text: text.to_string(),
        confirm: confirm.to_string(),
        reject: reject.to_string(),
    });

    // wait until a button is pressed
    loop {
        match get_event() {
            Event::Action(action) => {
                if action == Action::Reject {
                    return false;
                } else if action == Action::Confirm {
                    return true;
                }
            }
            _ => {}
        }
    }
}

pub fn ux_idle() {
    Ecall::ux_idle()
}
