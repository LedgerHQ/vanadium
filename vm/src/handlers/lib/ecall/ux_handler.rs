use alloc::{ffi::CString, string::String, vec::Vec};
use core::{cell::UnsafeCell, mem::MaybeUninit, ptr};

use ledger_secure_sdk_sys as sys;

use common::ux::Page;

#[cfg(any(target_os = "stax", target_os = "flex"))]
use super::bitmaps;

use super::CommEcallError;

const TOKEN_CONFIRM_REJECT: u8 = 0;
const TOKEN_QUIT: u8 = 1;
const TOKEN_SKIP: u8 = 2;
const TOKEN_NAVIGATION: u8 = 3;
const TOKEN_TITLE: u8 = 4;

// we use a static variable to store the event, so we can set it from the callback
static mut LAST_EVENT: Option<(common::ux::EventCode, common::ux::EventData)> = None;

pub fn get_last_event() -> Option<(common::ux::EventCode, common::ux::EventData)> {
    #[allow(static_mut_refs)] // only safe in single-threaded mode
    unsafe {
        LAST_EVENT.take()
    }
}

fn store_new_event(event_code: common::ux::EventCode, event_data: common::ux::EventData) {
    unsafe {
        // We store the new event if there was no stored event, or there is just a ticker
        // Otherwise we drop the new event
        if LAST_EVENT.is_none_or(|e| e.0 == common::ux::EventCode::Ticker) {
            crate::println!("Storing new event: {:?}", event_code);
            LAST_EVENT = Some((event_code, event_data));
        }
    }
}

// nbgl_layoutTouchCallback_t
unsafe extern "C" fn layout_touch_callback(token: core::ffi::c_int, index: u8) {
    crate::println!(
        "layout_touch_callback with token={} and index={}",
        token,
        index
    );

    match (token as u8, index) {
        (TOKEN_CONFIRM_REJECT, 0) => {
            crate::println!("Confirm button pressed");
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: common::ux::Action::Confirm,
                },
            );
        }
        (TOKEN_CONFIRM_REJECT, 1) => {
            crate::println!("Reject button pressed");
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: common::ux::Action::Reject,
                },
            );
        }
        (TOKEN_QUIT, _) => {
            crate::println!("Quit button pressed");
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: common::ux::Action::Quit,
                },
            );
        }
        (TOKEN_SKIP, _) => {
            crate::println!("Skip button pressed");
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: common::ux::Action::Skip,
                },
            );
        }
        (TOKEN_NAVIGATION, idx) => {
            crate::println!("Navigation button; index={}", idx);
            let cur_page = get_ux_handler().cur_page;

            let diff = idx as isize - cur_page as isize;
            let action = match diff {
                -1 => common::ux::Action::PreviousPage,
                1 => common::ux::Action::NextPage,
                _ => {
                    crate::println!("Unexpected index, cur_page is {}", cur_page);
                    return;
                }
            };
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData { action },
            );
        }
        (TOKEN_TITLE, _) => {
            crate::println!("Title pressed");
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: common::ux::Action::Title,
                },
            );
        }
        _ => crate::println!("Event unhandled",),
    }
}

// encapsulates all the global state related to Events and UX handling

pub struct UxHandler {
    cstrings: Vec<CString>,
    cur_page: u8,
}

// Global static variable to hold the singleton instance
static mut UX_HANDLER: MaybeUninit<UxHandler> = MaybeUninit::uninit();
static mut UX_HANDLER_INITIALIZED: bool = false;

pub fn init_ux_handler() -> &'static mut UxHandler {
    unsafe {
        if UX_HANDLER_INITIALIZED {
            panic!("UxHandler already initialized");
        }

        UX_HANDLER.write(UxHandler::new());
        UX_HANDLER_INITIALIZED = true;

        UX_HANDLER.assume_init_mut()
    }
}

pub fn get_ux_handler() -> &'static mut UxHandler {
    unsafe {
        if !UX_HANDLER_INITIALIZED {
            panic!("UxHandler not initialized");
        }
        UX_HANDLER.assume_init_mut()
    }
}

impl UxHandler {
    // We keep the constructor private in order to manage the singleton instance
    fn new() -> Self {
        Self {
            cstrings: Vec::new(),
            cur_page: 0,
        }
    }

    pub fn clear_cstrings(&mut self) {
        self.cstrings.clear();
    }

    #[inline(always)]
    pub unsafe fn alloc_cstring(
        &mut self,
        string: Option<&String>,
    ) -> Result<*const i8, CommEcallError> {
        if let Some(string) = string {
            self.cstrings.push(CString::new(string.clone())?);
            return Ok(self.cstrings[self.cstrings.len() - 1].as_ptr());
        }
        Ok(core::ptr::null())
    }

    pub fn show_page(&mut self, page: &Page) -> Result<(), CommEcallError> {
        match page {
            common::ux::Page::Spinner { text } => unsafe {
                #[cfg(not(any(target_os = "stax", target_os = "flex")))]
                todo!(); // TODO: implement for NanoS+/X

                #[cfg(any(target_os = "stax", target_os = "flex"))]
                sys::nbgl_pageDrawSpinner(self.alloc_cstring(Some(text))?, 0);
            },
            common::ux::Page::Info { icon, text } => unsafe {
                #[cfg(not(any(target_os = "stax", target_os = "flex")))]
                todo!(); // TODO: implement for NanoS+/X

                #[cfg(any(target_os = "stax", target_os = "flex"))]
                {
                    self.clear_cstrings();

                    let ticker_config = sys::nbgl_screenTickerConfiguration_t {
                        tickerCallback: None, // we could put a callback here if we had a timer
                        tickerValue: 0,       // no timer
                        tickerIntervale: 0,   // not periodic
                    };

                    let page_info = sys::nbgl_pageInfoDescription_t {
                        centeredInfo: sys::nbgl_contentCenteredInfo_t {
                            text1: self.alloc_cstring(Some(text))?,
                            text2: core::ptr::null(),
                            text3: core::ptr::null(),
                            icon: match icon {
                                common::ux::Icon::None => core::ptr::null(),
                                common::ux::Icon::Success => &bitmaps::CHECK_CIRCLE_64PX,
                                common::ux::Icon::Failure => &bitmaps::DENIED_CIRCLE_64PX,
                            },
                            onTop: false,
                            style: sys::LARGE_CASE_INFO,
                            offsetY: 0,
                        },
                        topRightStyle: sys::NO_BUTTON_STYLE,
                        bottomButtonStyle: sys::NO_BUTTON_STYLE,
                        topRightToken: 0,
                        bottomButtonsToken: 0,
                        footerText: core::ptr::null(),
                        footerToken: 1,
                        tapActionText: core::ptr::null(),
                        isSwipeable: true,
                        tapActionToken: 2,
                        actionButtonText: core::ptr::null(),
                        actionButtonIcon: core::ptr::null(),
                        actionButtonStyle: sys::BLACK_BACKGROUND,
                        tuneId: sys::TUNE_TAP_CASUAL,
                    };

                    sys::nbgl_pageDrawInfo(
                        None,
                        &ticker_config, // or core::ptr::null()
                        &page_info,
                    );
                }
            },
            common::ux::Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => unsafe {
                #[cfg(not(any(target_os = "stax", target_os = "flex")))]
                todo!(); // TODO: implement for NanoS+/X

                #[cfg(any(target_os = "stax", target_os = "flex"))]
                {
                    self.clear_cstrings();

                    let page_confirmation_description =
                        ledger_secure_sdk_sys::nbgl_pageConfirmationDescription_s {
                            centeredInfo: ledger_secure_sdk_sys::nbgl_contentCenteredInfo_t {
                                text1: self.alloc_cstring(Some(title))?,
                                text2: self.alloc_cstring(Some(text))?,
                                text3: core::ptr::null(),
                                icon: core::ptr::null(),
                                onTop: false,
                                style: ledger_secure_sdk_sys::LARGE_CASE_INFO,
                                offsetY: 0,
                            },
                            confirmationText: self.alloc_cstring(Some(confirm))?,
                            confirmationToken: TOKEN_CONFIRM_REJECT,
                            cancelText: self.alloc_cstring(Some(reject))?,
                            cancelToken: 255, // appears to be ignored
                            tuneId: ledger_secure_sdk_sys::TUNE_TAP_CASUAL,
                            modal: false,
                        };
                    ledger_secure_sdk_sys::nbgl_pageDrawConfirmation(
                        Some(layout_touch_callback),
                        &page_confirmation_description,
                    );
                }
            },
            common::ux::Page::GenericPage {
                navigation_info,
                page_content_info,
            } => unsafe {
                #[cfg(not(any(target_os = "stax", target_os = "flex")))]
                todo!(); // TODO: implement for NanoS+/X

                #[cfg(any(target_os = "stax", target_os = "flex"))]
                {
                    self.clear_cstrings();

                    let common::ux::NavInfo::NavWithButtons {
                        has_back_button,
                        has_page_indicator: _,
                        quit_text,
                    } = &navigation_info.nav_info;

                    if navigation_info.n_pages > 255
                        || navigation_info.active_page >= navigation_info.n_pages
                    {
                        return Err(CommEcallError::InvalidParameters("Invalid navigation info"));
                    }

                    get_ux_handler().cur_page = navigation_info.active_page as u8;

                    let common::ux::PageContent::TagValueList(tvl) =
                        &page_content_info.page_content;
                    let tag_value_list = tvl
                        .iter()
                        .map(|t| {
                            let mut res = ledger_secure_sdk_sys::nbgl_contentTagValue_t::default();
                            res.item = self.alloc_cstring(Some(&t.tag))?;
                            res.value = self.alloc_cstring(Some(&t.value))?;
                            Ok(res)
                        })
                        .collect::<Result<Vec<_>, CommEcallError>>()?;

                    ledger_secure_sdk_sys::nbgl_pageDrawGenericContent(
                        Some(layout_touch_callback),
                        &ledger_secure_sdk_sys::nbgl_pageNavigationInfo_t {
                            activePage: navigation_info.active_page as u8,
                            nbPages:  navigation_info.n_pages as u8,
                            quitToken: TOKEN_QUIT,
                            navType: ledger_secure_sdk_sys::NAV_WITH_BUTTONS,
                            progressIndicator: true,
                            tuneId: 0,
                            skipText: self.alloc_cstring(navigation_info.skip_text.as_ref())?,
                            skipToken: TOKEN_SKIP,
                            __bindgen_anon_1:
                            ledger_secure_sdk_sys::nbgl_pageMultiScreensDescription_s__bindgen_ty_1 {
                                navWithButtons: ledger_secure_sdk_sys::nbgl_pageNavWithButtons_s {
                                    quitButton: quit_text.is_some(),
                                    backButton: *has_back_button,
                                    visiblePageIndicator: false,
                                    navToken: TOKEN_NAVIGATION,
                                    quitText: self.alloc_cstring(quit_text.as_ref())?,
                                }
                            },
                        },
                        &mut ledger_secure_sdk_sys::nbgl_pageContent_t {
                            title: self.alloc_cstring(page_content_info.title.as_ref())?,
                            isTouchableTitle: page_content_info.is_title_touchable,
                            titleToken: TOKEN_TITLE,
                            tuneId: 0,
                            topRightToken: 255, // not implemented
                            topRightIcon: core::ptr::null(), // not implemented
                            type_: ledger_secure_sdk_sys::TAG_VALUE_LIST,
                            __bindgen_anon_1: ledger_secure_sdk_sys::nbgl_pageContent_s__bindgen_ty_1 {
                                tagValueList: ledger_secure_sdk_sys::nbgl_contentTagValueList_t {
                                    pairs: tag_value_list.as_ptr(),
                                    callback: None,
                                    nbPairs: tag_value_list.len() as u8,
                                    startIndex: 0, // unused if no callback
                                    nbMaxLinesForValue: 0,
                                    token: 255,
                                    smallCaseForValue: false,
                                    wrapping: true,
                                    actionCallback: None, // not implemented, no events from the tagvalues
                                }
                            },
                        },
                    );
                }
            },
        }
        Ok(())
    }
}

impl Drop for UxHandler {
    fn drop(&mut self) {
        unsafe {
            UX_HANDLER_INITIALIZED = false;
        }
    }
}
