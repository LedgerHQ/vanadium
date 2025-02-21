use crate::ecalls::{Ecall, EcallsInterface};
use alloc::{string::ToString, vec::Vec};

pub use common::ux::{
    Action, Event, EventCode, EventData, Icon, NavInfo, NavigationInfo, Page, PageContent,
    PageContentInfo, Serializable, TagValue,
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

// Like get_event, but it ignores any event that is not an Action
pub fn get_action() -> Action {
    loop {
        if let Event::Action(action) = get_event() {
            return action;
        }
    }
}

// Temporary function; similar to nbgl_useCaseReview
pub fn review_pairs(
    intro_text: &str,
    intro_subtext: &str,
    pairs: &[TagValue],
    final_text: &str,
    final_button_text: &str,
    long_press: bool,
) -> bool {
    let n_pair_pages = ((pairs.len() + 1) / 2) as u32;
    let n_pages = 1 + n_pair_pages + 1; // intro page + pair pages + final page

    let mut serialized_pages = Vec::with_capacity(n_pages as usize);

    // create intro page
    serialized_pages.push(
        Page::GenericPage {
            navigation_info: Some(NavigationInfo {
                active_page: 0,
                n_pages,
                skip_text: None,
                nav_info: NavInfo::NavWithButtons {
                    has_back_button: true,
                    has_page_indicator: true,
                    quit_text: Some("Reject".into()),
                },
            }),
            page_content_info: PageContentInfo {
                title: None,
                top_right_icon: Icon::None, // TODO: support icons
                page_content: PageContent::TextSubtext {
                    text: intro_text.into(),
                    subtext: intro_subtext.into(),
                },
            },
        }
        .serialized(),
    );

    // create a page for each pair of tag-value
    for i in 0..n_pair_pages {
        let mut pair_list = Vec::with_capacity(n_pair_pages as usize);
        pair_list.push(pairs[(i * 2) as usize].clone());
        if i * 2 + 1 < pairs.len() as u32 {
            pair_list.push(pairs[(i * 2 + 1) as usize].clone());
        }

        serialized_pages.push(
            Page::GenericPage {
                navigation_info: Some(NavigationInfo {
                    active_page: 1 + i,
                    n_pages,
                    skip_text: None,
                    nav_info: NavInfo::NavWithButtons {
                        has_back_button: true,
                        has_page_indicator: true,
                        quit_text: Some("Reject".into()),
                    },
                }),
                page_content_info: PageContentInfo {
                    title: None,
                    top_right_icon: Icon::None, // TODO: support icons
                    page_content: PageContent::TagValueList { list: pair_list },
                },
            }
            .serialized(),
        );
    }

    // create final page

    if long_press {
        serialized_pages.push(
            Page::GenericPage {
                navigation_info: Some(NavigationInfo {
                    active_page: n_pages - 1,
                    n_pages,
                    skip_text: None,
                    nav_info: NavInfo::NavWithButtons {
                        has_back_button: true,
                        has_page_indicator: true,
                        quit_text: Some("Reject".into()),
                    },
                }),
                page_content_info: PageContentInfo {
                    title: None,
                    top_right_icon: Icon::None, // TODO: support icons
                    page_content: PageContent::ConfirmationLongPress {
                        text: final_text.into(),
                        long_press_text: final_button_text.into(),
                    },
                },
            }
            .serialized(),
        );
    } else {
        serialized_pages.push(
            Page::GenericPage {
                navigation_info: Some(NavigationInfo {
                    active_page: n_pages - 1,
                    n_pages,
                    skip_text: None,
                    nav_info: NavInfo::NavWithButtons {
                        has_back_button: true,
                        has_page_indicator: true,
                        quit_text: Some("Reject".into()),
                    },
                }),
                page_content_info: PageContentInfo {
                    title: None,
                    top_right_icon: Icon::None, // TODO: support icons
                    page_content: PageContent::ConfirmationButton {
                        text: final_text.into(),
                        button_text: final_button_text.into(),
                    },
                },
            }
            .serialized(),
        );
    }

    let mut active_page = 0;
    loop {
        show_page_raw(&serialized_pages[active_page]);
        active_page = loop {
            match get_event() {
                Event::Action(Action::PreviousPage) => {
                    break active_page - 1;
                }
                Event::Action(Action::NextPage) => {
                    break active_page + 1;
                }
                Event::Action(Action::Quit) => {
                    return false;
                }
                Event::Action(Action::Confirm) => {
                    return true;
                }
                _ => {} // ignore other events for now
            }
        }
    }
}

// TODO: we might want to not make this public, and have different functions for different types of pages
pub fn show_page(page: &Page) {
    let mut serialized_page = Vec::new();
    page.serialize(&mut serialized_page);
    Ecall::show_page(serialized_page.as_ptr(), serialized_page.len());
}

pub fn show_page_raw(page: &[u8]) {
    Ecall::show_page(page.as_ptr(), page.len());
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
    show_page(&Page::GenericPage {
        navigation_info: None,
        page_content_info: PageContentInfo {
            title: None,
            top_right_icon: Icon::None, // TODO: support icons
            page_content: PageContent::TextSubtext {
                text: "Application".into(),
                subtext: "is ready".into(),
            },
        },
    })
}
