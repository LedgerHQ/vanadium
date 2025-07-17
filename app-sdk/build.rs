use std::{fs::File, io::Write, path::Path};

use common::ux::*;

mod build_utils;

use build_utils::{gen_u8_slice, make_object_maker};

const PAGE_MAKERS: &[(&'static str, WrappedPage)] = &[
    (
        "spinner",
        WrappedPage::Spinner {
            text: rt_str("text", "&str"),
        },
    ),
    (
        "info",
        WrappedPage::Info {
            icon: rt("icon", "Icon"),
            text: rt_str("text", "&str"),
        },
    ),
    (
        "confirm_reject",
        WrappedPage::ConfirmReject {
            title: rt_str("title", "&str"),
            text: rt_str("text", "&str"),
            confirm: rt_str("confirm", "&str"),
            reject: rt_str("reject", "&str"),
        },
    ),
    (
        "review_pairs_intro",
        WrappedPage::GenericPage {
            navigation_info: Some(WrappedNavigationInfo {
                active_page: rt("active_page", "u32"),
                n_pages: rt("n_pages", "u32"),
                skip_text: None,
                nav_info: WrappedNavInfo::NavWithButtons {
                    has_back_button: ct(true),
                    has_page_indicator: ct(true),
                    quit_text: Some(ct_str("Reject")),
                },
            }),
            page_content_info: WrappedPageContentInfo {
                title: None,
                top_right_icon: ct(Icon::None), // TODO: support icons
                page_content: WrappedPageContent::TextSubtext {
                    text: rt_str("intro_text", "&str"),
                    subtext: rt_str("intro_subtext", "&str"),
                },
            },
        },
    ),
    (
        "review_pairs_content",
        WrappedPage::GenericPage {
            navigation_info: Some(WrappedNavigationInfo {
                active_page: rt("active_page", "u32"),
                n_pages: rt("n_pages", "u32"),
                skip_text: None,
                nav_info: WrappedNavInfo::NavWithButtons {
                    has_back_button: ct(true),
                    has_page_indicator: ct(true),
                    quit_text: Some(ct_str("Reject")),
                },
            }),
            page_content_info: WrappedPageContentInfo {
                title: None,
                top_right_icon: ct(Icon::None), // TODO: support icons
                page_content: WrappedPageContent::TagValueList {
                    list: rt("pairs", "&[TagValue]"),
                },
            },
        },
    ),
    (
        "review_pairs_final_longpress",
        WrappedPage::GenericPage {
            navigation_info: Some(WrappedNavigationInfo {
                active_page: rt("active_page", "u32"),
                n_pages: rt("n_pages", "u32"),
                skip_text: None,
                nav_info: WrappedNavInfo::NavWithButtons {
                    has_back_button: ct(true),
                    has_page_indicator: ct(true),
                    quit_text: Some(ct_str("Reject")),
                },
            }),
            page_content_info: WrappedPageContentInfo {
                title: None,
                top_right_icon: ct(Icon::None), // TODO: support icons
                page_content: WrappedPageContent::ConfirmationLongPress {
                    text: rt_str("final_text", "&str"),
                    long_press_text: rt_str("final_button_text", "&str"),
                },
            },
        },
    ),
    (
        "review_pairs_final_confirmationbutton",
        WrappedPage::GenericPage {
            navigation_info: Some(WrappedNavigationInfo {
                active_page: rt("active_page", "u32"),
                n_pages: rt("n_pages", "u32"),
                skip_text: None,
                nav_info: WrappedNavInfo::NavWithButtons {
                    has_back_button: ct(true),
                    has_page_indicator: ct(true),
                    quit_text: Some(ct_str("Reject")),
                },
            }),
            page_content_info: WrappedPageContentInfo {
                title: None,
                top_right_icon: ct(Icon::None), // TODO: support icons
                page_content: WrappedPageContent::ConfirmationButton {
                    text: rt_str("final_text", "&str"),
                    button_text: rt_str("final_button_text", "&str"),
                },
            },
        },
    ),
];

const STEP_MAKERS: &[(&'static str, WrappedStep)] = &[
    (
        "text_subtext",
        WrappedStep::TextSubtext {
            pos: rt("pos", "u8"),
            text: rt_str("text", "&str"),
            subtext: rt_str("subtext", "&str"),
            style: ct(REGULAR_INFO),
        },
    ),
    (
        "info_single",
        WrappedStep::CenteredInfo {
            pos: ct(0), // SINGLE_STEP
            icon: ct(Icon::None),
            text: Some(rt_str("text", "&str")),
            subtext: None,
            style: ct(BOLD_TEXT1_INFO),
        },
    ),
    (
        "centered_info_nosubtext",
        WrappedStep::CenteredInfo {
            pos: rt("pos", "u8"),
            icon: rt("icon", "Icon"),
            text: Some(rt_str("text", "&str")),
            subtext: None,
            style: ct(BOLD_TEXT1_INFO),
        },
    ),
    (
        "confirm",
        WrappedStep::CenteredInfo {
            pos: rt("pos", "u8"),
            text: Some(ct_str("Confirm")),
            subtext: None,
            icon: ct(Icon::Confirm),
            style: ct(BOLD_TEXT1_INFO),
        },
    ),
    (
        "reject",
        WrappedStep::CenteredInfo {
            pos: rt("pos", "u8"),
            text: Some(ct_str("Reject")),
            subtext: None,
            icon: ct(Icon::Reject),
            style: ct(BOLD_TEXT1_INFO),
        },
    ),
    (
        "spinner",
        WrappedStep::CenteredInfo {
            pos: ct(0), // SINGLE_STEP,
            text: Some(rt_str("text", "&str")),
            subtext: None,
            icon: ct(Icon::Processing),
            style: ct(BOLD_TEXT1_INFO),
        },
    ),
];

// Precomputed pages with no variable part, so they can be directly
// embedded in the binary as constants.
fn make_const_pages(file: &mut File) {
    let default_pages: &[(&'static str, Page)] = &[(
        // "Application is ready"
        "APP_DASHBOARD",
        Page::GenericPage {
            navigation_info: None,
            page_content_info: PageContentInfo {
                title: None,
                top_right_icon: Icon::None,
                page_content: PageContent::TextSubtext {
                    text: "Application".into(),
                    subtext: "is ready".into(),
                },
            },
        },
    )];

    for (page_name, page) in default_pages {
        let serialized = page.serialized();

        writeln!(
            file,
            "pub const RAW_PAGE_{}: [u8; {}] = {};",
            page_name,
            serialized.len(),
            gen_u8_slice(&serialized)
        )
        .expect("Could not write");
    }

    writeln!(file).expect("Could not write");
}

// Precomputed steps with no variable part, so they can be directly
// embedded in the binary as constants.
fn make_const_steps(file: &mut File) {
    let default_steps: &[(&'static str, Step)] = &[(
        // "Application is ready"
        "APP_DASHBOARD",
        Step::TextSubtext {
            pos: 0, // SINGLE_STEP
            text: "Application".into(),
            subtext: "is ready".into(),
            style: REGULAR_INFO,
        },
    )];

    for (step_name, step) in default_steps {
        let serialized = step.serialized();

        writeln!(
            file,
            "pub const RAW_STEP_{}: [u8; {}] = {};",
            step_name,
            serialized.len(),
            gen_u8_slice(&serialized)
        )
        .expect("Could not write");
    }

    writeln!(file).expect("Could not write");
}

fn main() {
    let dest_path = Path::new("src/ux_generated.rs");
    let mut file = File::create(&dest_path).expect("Could not create file");

    writeln!(
        file,
        "// This file is automatically generated by the build.rs script.

// assignments to cur_len are not always used; disable th warning
#![allow(unused_assignments)]

use crate::ecalls;
use alloc::vec::Vec;
use common::ux::*;
use core::mem::MaybeUninit;

#[inline(always)]
fn show_page_raw(page: &[u8]) {{
    ecalls::show_page(page.as_ptr(), page.len());
}}

#[inline(always)]
fn show_step_raw(page: &[u8]) {{
    ecalls::show_step(page.as_ptr(), page.len());
}}
"
    )
    .expect("Could not write");

    make_const_pages(&mut file);
    make_const_steps(&mut file);

    for (fn_name, wrapped_page) in PAGE_MAKERS.iter() {
        make_object_maker(
            "page",
            &mut file,
            &wrapped_page.serialize_wrapped(),
            fn_name,
        );
    }

    for (fn_name, wrapped_step) in STEP_MAKERS.iter() {
        make_object_maker(
            "step",
            &mut file,
            &wrapped_step.serialize_wrapped(),
            fn_name,
        );
    }
}
