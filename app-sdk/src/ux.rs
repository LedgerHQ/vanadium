use core::panic;

use crate::{
    ecalls,
    ux_generated::{
        make_page_review_pairs_content, make_page_review_pairs_final_confirmationbutton,
        make_page_review_pairs_final_longpress, make_page_review_pairs_intro,
    },
};
use alloc::vec::Vec;

use common::ecall_constants::DEVICE_PROPERTY_ID;
pub use common::ux::{
    Action, Deserializable, Event, EventCode, EventData, Icon, NavInfo, NavigationInfo, Page,
    PageContent, PageContentInfo, TagValue,
};

use crate::ux_generated;

// Returns true if the device supports the page UX model, false if it supports the step UX model.
// It panics for unsupported devices
pub fn has_page_api() -> bool {
    match ecalls::get_device_property(DEVICE_PROPERTY_ID) {
        0 => true,           // native target
        0x2c970060 => true,  // Ledger Stax
        0x2c970070 => true,  // Ledger Flex
        0x2c970080 => true,  // Ledger Apex_p
        0x2c970040 => false, // Ledger Nano X
        0x2c970050 => false, // Ledger Nano S+
        _ => panic!("Unsupported device"),
    }
}

#[inline(always)]
fn show_page_raw(page: &[u8]) {
    ecalls::show_page(page.as_ptr(), page.len());
}

#[inline(always)]
fn show_step_raw(step: &[u8]) {
    ecalls::show_step(step.as_ptr(), step.len());
}

/// Blocks until an event is received, then returns it.
pub fn get_event() -> Event {
    loop {
        let mut event_data = EventData::default();
        let event_code = EventCode::from(ecalls::get_event(&mut event_data));
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

// waits for a number of ticker events
pub fn wait(n: u32) {
    let mut n_tickers = 0u32;
    loop {
        let mut event_data = EventData::default();
        let event_code = EventCode::from(ecalls::get_event(&mut event_data));
        match event_code {
            EventCode::Ticker => {
                n_tickers += 1;
                if n_tickers >= n {
                    return;
                }
            }
            _ => {}
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

// implementation of review_pairs() for the page API
fn __page_review_pairs(
    intro_text: &str,
    intro_subtext: &str,
    pairs: &[TagValue],
    final_text: &str,
    final_button_text: &str,
    long_press: bool,
) -> bool {
    // As this is still too slow to compute everything at once, we use a 'streaming' approach where we compute
    // the next page only after showing the current one.
    // While we're computing the page, we're not able to listen to touch events, so it will currently miss
    // user touches something before the precomputation of the next page is completed.
    // TODO: improve this

    // Calculate total number of pages
    let n_pair_pages = ((pairs.len() + 1) / 2) as u32;
    let n_pages = 2 + n_pair_pages; // intro + pair pages + final

    // Initialize with capacity, but start empty
    let mut serialized_pages = Vec::with_capacity(n_pages as usize);

    // Compute and add the first page (intro)
    serialized_pages.push(make_page_review_pairs_intro(
        0,
        n_pages,
        intro_text,
        intro_subtext,
    ));

    let mut active_page = 0;

    loop {
        // Show the current page
        show_page_raw(&serialized_pages[active_page]);

        // Compute the next page if it exists and hasn't been computed
        if active_page + 1 < n_pages as usize && serialized_pages.len() == active_page + 1 {
            let next_page_index = active_page + 1;
            let next_page = if next_page_index == (n_pages - 1) as usize {
                // Final page
                if long_press {
                    make_page_review_pairs_final_longpress(
                        next_page_index as u32,
                        n_pages,
                        final_text,
                        final_button_text,
                    )
                } else {
                    make_page_review_pairs_final_confirmationbutton(
                        next_page_index as u32,
                        n_pages,
                        final_text,
                        final_button_text,
                    )
                }
            } else {
                // Pair page (indices 1 to n_pair_pages)
                let chunk_index = next_page_index - 1;
                let pair_chunk = pairs.chunks(2).nth(chunk_index as usize).unwrap();
                make_page_review_pairs_content(next_page_index as u32, n_pages, pair_chunk)
            };
            serialized_pages.push(next_page);
        }

        // Process events
        loop {
            match get_event() {
                Event::Action(Action::PreviousPage) if active_page > 0 => {
                    active_page -= 1;
                    break;
                }
                Event::Action(Action::NextPage) if active_page + 1 < n_pages as usize => {
                    active_page += 1;
                    break;
                }
                Event::Action(Action::Quit) => {
                    return false;
                }
                Event::Action(Action::Confirm) => {
                    return true;
                }
                _ => {} // Ignore other events
            }
        }
    }
}

// implementation of review_pairs() for the step API
fn __step_review_pairs(
    intro_text: &str,
    intro_subtext: &str,
    pairs: &[TagValue],
    _final_text: &str,
    final_button_text: &str,
    _long_press: bool,
) -> bool {
    // Calculate total number of pages
    let n_pair_steps = pairs.len() as u32; // TODO: this doesn't quite work for pairs that are split into multiple screens
    let n_steps = 3 + n_pair_steps; // intro + pair steps + confirm + reject

    let mut cur_step = 0;

    loop {
        let pos = step_pos(n_steps, cur_step);
        match cur_step {
            0 => {
                ux_generated::show_step_text_subtext(
                    step_pos(n_steps, 0),
                    intro_text,
                    intro_subtext,
                );
            }
            step if step >= 1 && step <= n_pair_steps => {
                let pair_index = cur_step - 1;
                let pair = pairs.get(pair_index as usize).unwrap();
                ux_generated::show_step_text_subtext(pos, &pair.tag, &pair.value);
            }
            step if step == n_pair_steps + 1 => {
                ux_generated::show_step_centered_info_nosubtext(
                    pos,
                    final_button_text,
                    Icon::Confirm,
                );
            }
            step if step == n_pair_steps + 2 => {
                ux_generated::show_step_reject(pos);
            }
            _ => {
                panic!("Invalid step");
            }
        }

        loop {
            match get_event() {
                Event::Action(action) => {
                    if action == Action::NextPage && cur_step < n_steps - 1 {
                        cur_step += 1;
                        break;
                    } else if action == Action::PreviousPage && cur_step > 0 {
                        cur_step -= 1;
                        break;
                    } else if action == Action::Confirm {
                        if cur_step == n_pair_steps + 1 {
                            return true; // Confirm
                        } else if cur_step == n_pair_steps + 2 {
                            return false; // Reject
                        }
                    }
                }
                _ => {}
            }
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
    if has_page_api() {
        __page_review_pairs(
            intro_text,
            intro_subtext,
            pairs,
            final_text,
            final_button_text,
            long_press,
        )
    } else {
        __step_review_pairs(
            intro_text,
            intro_subtext,
            pairs,
            final_text,
            final_button_text,
            long_press,
        )
    }
}

pub fn show_spinner(text: &str) {
    if has_page_api() {
        ux_generated::show_page_spinner(text);
    } else {
        ux_generated::show_step_spinner(text);
    }
}

pub fn show_info(icon: Icon, text: &str) {
    if has_page_api() {
        ux_generated::show_page_info(icon, text);
    } else {
        ux_generated::show_step_info_single(text);
    }

    wait(20); // Wait for 20 ticker events (about 2 seconds)
}

// computes the correct constant among SINGLE_STEP, FIRST_STEP, LAST_STEP, NEITHER_FIRST_NOR_LAST_STEP
const fn step_pos(n_steps: u32, cur_step: u32) -> u8 {
    let has_left_arrow = (cur_step > 0) as u8;
    let has_right_arrow = (cur_step + 1 < n_steps) as u8;

    has_left_arrow << 1 | has_right_arrow
}

pub fn show_confirm_reject(title: &str, text: &str, confirm: &str, reject: &str) -> bool {
    if has_page_api() {
        ux_generated::show_page_confirm_reject(title, text, confirm, reject);

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
    } else {
        let n_steps = 3;
        let mut cur_step = 0;

        loop {
            match cur_step {
                0 => {
                    ux_generated::show_step_text_subtext(step_pos(n_steps, cur_step), title, text);
                }
                1 => ux_generated::show_step_confirm(step_pos(n_steps, cur_step)),
                2 => ux_generated::show_step_reject(step_pos(n_steps, cur_step)),
                _ => {
                    panic!("Invalid step");
                }
            }

            loop {
                match get_event() {
                    Event::Action(action) => {
                        if action == Action::NextPage && cur_step < n_steps - 1 {
                            cur_step += 1;
                            break;
                        } else if action == Action::PreviousPage && cur_step > 0 {
                            cur_step -= 1;
                            break;
                        } else if action == Action::Confirm {
                            if cur_step == 1 {
                                return true; // Confirm
                            } else if cur_step == 2 {
                                return false; // Reject
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

pub fn ux_idle() {
    if has_page_api() {
        show_page_raw(&ux_generated::RAW_PAGE_APP_DASHBOARD);
    } else {
        show_step_raw(&ux_generated::RAW_STEP_APP_DASHBOARD);
    }
}

pub fn ux_home(description: &str) {
    if has_page_api() {
        ux_generated::show_page_home(description);
    } else {
        // not implemented yet for step API
        todo!();
    }
}
