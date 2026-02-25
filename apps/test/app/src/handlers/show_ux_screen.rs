use alloc::{vec, vec::Vec};
use sdk::executor::block_on;

pub fn handle_show_ux_screen(data: &[u8]) -> Vec<u8> {
    if data.len() != 1 {
        return vec![];
    }

    let screen_id = data[0];
    match screen_id {
        0 => {
            block_on(sdk::ux::show_info(sdk::ux::Icon::Success, "Oh yeah!"));
            block_on(sdk::ux::wait(10));
        }
        1 => {
            block_on(sdk::ux::show_info(sdk::ux::Icon::Failure, "Oh no!"));
            block_on(sdk::ux::wait(10));
        }
        2 => {
            sdk::ux::show_spinner("Loading...");
            block_on(sdk::ux::wait(10));
        }
        3 => {
            block_on(sdk::ux::show_confirm_reject(
                "Confirm",
                "Do you want to confirm?",
                "Yes",
                "No",
            ));
        }
        4 => {
            block_on(sdk::ux::review_pairs(
                "Review the pairs",
                "It's important",
                &vec![
                    sdk::ux::TagValue {
                        tag: "tag1".into(),
                        value: "value1".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag2".into(),
                        value: "value2".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag3".into(),
                        value: "value3".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag4".into(),
                        value: "value4".into(),
                    },
                    sdk::ux::TagValue {
                        tag: "tag5".into(),
                        value: "value5".into(),
                    },
                ],
                "Hope you checked",
                "Confirm",
                true,
            ));
        }
        _ => panic!("Unknown screen id"),
    }

    sdk::ux::ux_idle();

    vec![]
}
