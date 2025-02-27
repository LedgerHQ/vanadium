use std::{fs::File, io::Write, path::Path};

use common::ux::*;

mod build_utils;

use build_utils::{gen_u8_slice, make_page_maker};

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

fn main() {
    let dest_path = Path::new("src/ux_generated.rs");
    let mut file = File::create(&dest_path).expect("Could not create file");

    writeln!(
        file,
        "// This file is automatically generated by the build.rs script.

use crate::ecalls::{{Ecall, EcallsInterface}};
use alloc::vec::Vec;
use common::ux::*;
use core::mem::MaybeUninit;

#[inline(always)]
fn show_page_raw(page: &[u8]) {{
    Ecall::show_page(page.as_ptr(), page.len());
}}
"
    )
    .expect("Could not write");

    make_const_pages(&mut file);

    for (fn_name, wrapped_page) in PAGE_MAKERS.iter() {
        make_page_maker(&mut file, &wrapped_page.serialize_wrapped(), fn_name);
    }
}
