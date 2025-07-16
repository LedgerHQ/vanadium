#[cfg(not(any(target_os = "stax", target_os = "flex")))]
use core::ffi::c_void;

use alloc::{ffi::CString, string::String, vec::Vec};

use ledger_secure_sdk_sys as sys;

use common::ux::{Page, Step};

use super::bitmaps;

use super::CommEcallError;

const TOKEN_CONFIRM_REJECT: u8 = 0;
const TOKEN_QUIT: u8 = 1;
const TOKEN_SKIP: u8 = 2;
const TOKEN_NAVIGATION: u8 = 3;
const TOKEN_TITLE: u8 = 4;

static mut LAST_EVENT: Option<(common::ux::EventCode, common::ux::EventData)> = None;

pub fn get_last_event() -> Option<(common::ux::EventCode, common::ux::EventData)> {
    // Safe in a single-threaded environment
    #[allow(static_mut_refs)]
    unsafe {
        LAST_EVENT.take()
    }
}

pub fn store_new_event(event_code: common::ux::EventCode, event_data: common::ux::EventData) {
    // We store the new event if there was no stored event, or there is just a ticker
    // Otherwise we drop the new event
    #[allow(static_mut_refs)]
    unsafe {
        if LAST_EVENT.is_none() || LAST_EVENT.as_ref().unwrap().0 == common::ux::EventCode::Ticker {
            LAST_EVENT = Some((event_code, event_data));
        }
    }
}

// nbgl_layoutTouchCallback_t
#[cfg(any(target_os = "stax", target_os = "flex"))]
unsafe extern "C" fn layout_touch_callback(token: core::ffi::c_int, index: u8) {
    crate::println!(
        "layout_touch_callback with token={} and index={}",
        token,
        index
    );

    let action = match (token as u8, index) {
        (TOKEN_CONFIRM_REJECT, 0) => common::ux::Action::Confirm,
        (TOKEN_CONFIRM_REJECT, 1) => common::ux::Action::Reject,
        (TOKEN_QUIT, _) => common::ux::Action::Quit,
        (TOKEN_SKIP, _) => common::ux::Action::Skip,
        (TOKEN_NAVIGATION, idx) => {
            let cur_page = get_ux_handler().cur_page;

            let diff = idx as isize - cur_page as isize;
            match diff {
                -1 => common::ux::Action::PreviousPage,
                1 => common::ux::Action::NextPage,
                _ => {
                    crate::println!("Unexpected index, cur_page is {}", cur_page);
                    return;
                }
            }
        }
        (TOKEN_TITLE, _) => common::ux::Action::TitleBack,
        _ => {
            crate::println!("Event unhandled");
            return;
        }
    };

    store_new_event(
        common::ux::EventCode::Action,
        common::ux::EventData { action },
    );
}

// encapsulates all the global state related to Events and UX handling

pub struct UxHandler {
    cstrings: Vec<CString>,
    #[cfg(not(any(target_os = "stax", target_os = "flex")))]
    step_handle: *mut c_void, // handle returned by nbgl when drawing a step; should be freed before drawing a new step
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    cur_page: u8,
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    page_handle: *mut sys::nbgl_page_t, // handle returned by nbgl when drawing a page; should be freed before drawing a new page
}

// Global static variable to hold the singleton instance
static mut UX_HANDLER: core::mem::MaybeUninit<UxHandler> = core::mem::MaybeUninit::uninit();
static mut UX_HANDLER_INITIALIZED: bool = false;

pub fn init_ux_handler() -> &'static mut UxHandler {
    unsafe {
        if UX_HANDLER_INITIALIZED {
            panic!("UxHandler already initialized");
        }

        #[allow(static_mut_refs)] // it's safe as we are in single-threaded mode
        UX_HANDLER.write(UxHandler::new());
        UX_HANDLER_INITIALIZED = true;

        #[allow(static_mut_refs)] // it's safe as we are in single-threaded mode
        UX_HANDLER.assume_init_mut()
    }
}

pub fn get_ux_handler() -> &'static mut UxHandler {
    unsafe {
        if !UX_HANDLER_INITIALIZED {
            panic!("UxHandler not initialized");
        }

        #[allow(static_mut_refs)] // it's safe as we are in single-threaded mode
        UX_HANDLER.assume_init_mut()
    }
}

pub fn drop_ux_handler() {
    unsafe {
        if !UX_HANDLER_INITIALIZED {
            return;
        }

        #[allow(static_mut_refs)] // it's safe as we are in single-threaded mode
        let handler = UX_HANDLER.assume_init_mut();
        handler.release_handle();
        handler.clear_cstrings();

        UX_HANDLER_INITIALIZED = false;
    }
}

impl UxHandler {
    // We keep the constructor private in order to manage the singleton instance
    fn new() -> Self {
        #[cfg(not(any(target_os = "stax", target_os = "flex")))]
        return Self {
            cstrings: Vec::new(),
            step_handle: core::ptr::null_mut(),
        };
        #[cfg(any(target_os = "stax", target_os = "flex"))]
        return Self {
            cstrings: Vec::new(),
            cur_page: 0,
            page_handle: core::ptr::null_mut(),
        };
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

    // This should always be called before drawing a new step or page, in order to
    // make sure that the resources of the previous step/page are released
    fn release_handle(&mut self) {
        #[cfg(any(target_os = "stax", target_os = "flex"))]
        unsafe {
            if !self.page_handle.is_null() {
                sys::nbgl_pageRelease(self.page_handle);
                self.page_handle = core::ptr::null_mut();
            }
        }

        #[cfg(not(any(target_os = "stax", target_os = "flex")))]
        unsafe {
            if !self.step_handle.is_null() {
                sys::nbgl_stepRelease(self.step_handle);
                self.step_handle = core::ptr::null_mut();
            }
        }
    }

    #[cfg(not(any(target_os = "stax", target_os = "flex")))]
    pub fn show_page(&mut self, page: &Page) -> Result<(), CommEcallError> {
        Err(CommEcallError::UnhandledEcall)
    }

    #[cfg(any(target_os = "stax", target_os = "flex"))]
    pub fn show_page(&mut self, page: &Page) -> Result<(), CommEcallError> {
        match page {
            common::ux::Page::Spinner { text } => unsafe {
                self.release_handle();
                self.page_handle = sys::nbgl_pageDrawSpinner(self.alloc_cstring(Some(text))?, 0);
            },
            common::ux::Page::Info { icon, text } => unsafe {
                self.clear_cstrings();
                self.release_handle();

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
                            common::ux::Icon::Accept => core::ptr::null(), // only for small screen devices
                            common::ux::Icon::Reject => core::ptr::null(), // only for small screen devices
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

                self.page_handle = sys::nbgl_pageDrawInfo(
                    None,
                    &ticker_config, // or core::ptr::null()
                    &page_info,
                );
            },
            common::ux::Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => unsafe {
                self.clear_cstrings();
                self.release_handle();

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
                self.page_handle = ledger_secure_sdk_sys::nbgl_pageDrawConfirmation(
                    Some(layout_touch_callback),
                    &page_confirmation_description,
                );
            },
            common::ux::Page::GenericPage {
                navigation_info,
                page_content_info,
            } => unsafe {
                self.clear_cstrings();
                self.release_handle();

                let nav_info = navigation_info.as_ref().map(|ni| {
                        get_ux_handler().cur_page = ni.active_page as u8;

                        let common::ux::NavInfo::NavWithButtons {
                            has_back_button,
                            has_page_indicator,
                            quit_text,
                        } = &ni.nav_info;

                        if ni.n_pages > 255
                            || ni.active_page >= ni.n_pages
                        {
                            return Err(CommEcallError::InvalidParameters(
                                "Invalid navigation info",
                            ));
                        }

                        Ok(ledger_secure_sdk_sys::nbgl_pageNavigationInfo_t {
                            activePage: ni.active_page as u8,
                            nbPages:  ni.n_pages as u8,
                            quitToken: TOKEN_QUIT,
                            navType: ledger_secure_sdk_sys::NAV_WITH_BUTTONS,
                            progressIndicator: true,
                            tuneId: 0,
                            skipText: self.alloc_cstring(ni.skip_text.as_ref())?,
                            skipToken: TOKEN_SKIP,
                            __bindgen_anon_1:
                            ledger_secure_sdk_sys::nbgl_pageMultiScreensDescription_s__bindgen_ty_1 {
                                navWithButtons: ledger_secure_sdk_sys::nbgl_pageNavWithButtons_s {
                                    quitButton: quit_text.is_some(),
                                    backButton: *has_back_button,
                                    visiblePageIndicator: *has_page_indicator, // only has any effect on Flex
                                    navToken: TOKEN_NAVIGATION,
                                    quitText: self.alloc_cstring(quit_text.as_ref())?,
                                }
                            },
                        })
                    }).transpose()?;
                let navigation_info = match nav_info {
                    Some(ref ni) => ni as *const _,
                    None => core::ptr::null(),
                };

                match &page_content_info.page_content {
                    common::ux::PageContent::TextSubtext { text, subtext } => {
                        self.page_handle = ledger_secure_sdk_sys::nbgl_pageDrawGenericContent(
                            Some(layout_touch_callback),
                            navigation_info,
                            &mut ledger_secure_sdk_sys::nbgl_pageContent_t {
                                title: self.alloc_cstring(page_content_info.title.as_ref())?,
                                isTouchableTitle: false, // unused in nbgl
                                titleToken: TOKEN_TITLE,
                                tuneId: 0,
                                topRightToken: 255,              // not implemented
                                topRightIcon: core::ptr::null(), // not implemented
                                type_: ledger_secure_sdk_sys::CENTERED_INFO,
                                __bindgen_anon_1:
                                    ledger_secure_sdk_sys::nbgl_pageContent_s__bindgen_ty_1 {
                                        centeredInfo:
                                            ledger_secure_sdk_sys::nbgl_contentCenteredInfo_t {
                                                text1: self.alloc_cstring(Some(text))?,
                                                text2: self.alloc_cstring(Some(subtext))?,
                                                text3: core::ptr::null(),
                                                icon: core::ptr::null(),
                                                onTop: false,
                                                style: ledger_secure_sdk_sys::LARGE_CASE_INFO,
                                                offsetY: 0,
                                            },
                                    },
                            },
                        );
                    }
                    common::ux::PageContent::TagValueList { list } => {
                        let tag_value_list = list
                            .iter()
                            .map(|t| {
                                let mut res =
                                    ledger_secure_sdk_sys::nbgl_contentTagValue_t::default();
                                res.item = self.alloc_cstring(Some(&t.tag))?;
                                res.value = self.alloc_cstring(Some(&t.value))?;
                                Ok(res)
                            })
                            .collect::<Result<Vec<_>, CommEcallError>>()?;

                        self.page_handle = ledger_secure_sdk_sys::nbgl_pageDrawGenericContent(
                            Some(layout_touch_callback),
                            navigation_info,
                            &mut ledger_secure_sdk_sys::nbgl_pageContent_t {
                                title: self.alloc_cstring(page_content_info.title.as_ref())?,
                                isTouchableTitle: false, // unused in nbgl
                                titleToken: TOKEN_TITLE,
                                tuneId: 0,
                                topRightToken: 255,              // not implemented
                                topRightIcon: core::ptr::null(), // not implemented
                                type_: ledger_secure_sdk_sys::TAG_VALUE_LIST,
                                __bindgen_anon_1:
                                    ledger_secure_sdk_sys::nbgl_pageContent_s__bindgen_ty_1 {
                                        tagValueList:
                                            ledger_secure_sdk_sys::nbgl_contentTagValueList_t {
                                                pairs: tag_value_list.as_ptr(),
                                                callback: None,
                                                nbPairs: tag_value_list.len() as u8,
                                                startIndex: 0, // unused if no callback
                                                nbMaxLinesForValue: 0,
                                                token: 255,
                                                smallCaseForValue: false,
                                                wrapping: true,
                                                actionCallback: None, // not implemented, no events from the tagvalues
                                            },
                                    },
                            },
                        );
                    }
                    common::ux::PageContent::ConfirmationButton { text, button_text } => {
                        self.page_handle = ledger_secure_sdk_sys::nbgl_pageDrawGenericContent(
                            Some(layout_touch_callback),
                            navigation_info,
                            &mut ledger_secure_sdk_sys::nbgl_pageContent_t {
                                title: self.alloc_cstring(page_content_info.title.as_ref())?,
                                isTouchableTitle: false, // unused in nbgl
                                titleToken: TOKEN_TITLE,
                                tuneId: 0,
                                topRightToken: 255,              // not implemented
                                topRightIcon: core::ptr::null(), // not implemented
                                type_: ledger_secure_sdk_sys::INFO_BUTTON,
                                __bindgen_anon_1:
                                    ledger_secure_sdk_sys::nbgl_pageContent_s__bindgen_ty_1 {
                                        infoButton:
                                            ledger_secure_sdk_sys::nbgl_contentInfoButton_t {
                                                text: self.alloc_cstring(Some(text))?,
                                                icon: core::ptr::null(),
                                                buttonText: self
                                                    .alloc_cstring(Some(button_text))?,
                                                buttonToken: 0, // TODO,
                                                tuneId: 0,
                                            },
                                    },
                            },
                        );
                    }
                    common::ux::PageContent::ConfirmationLongPress {
                        text,
                        long_press_text,
                    } => {
                        self.page_handle = ledger_secure_sdk_sys::nbgl_pageDrawGenericContent(
                            Some(layout_touch_callback),
                            navigation_info,
                            &mut ledger_secure_sdk_sys::nbgl_pageContent_t {
                                title: self.alloc_cstring(page_content_info.title.as_ref())?,
                                isTouchableTitle: false, // unused in nbgl
                                titleToken: TOKEN_TITLE,
                                tuneId: 0,
                                topRightToken: 255,              // not implemented
                                topRightIcon: core::ptr::null(), // not implemented
                                type_: ledger_secure_sdk_sys::INFO_LONG_PRESS,
                                __bindgen_anon_1:
                                    ledger_secure_sdk_sys::nbgl_pageContent_s__bindgen_ty_1 {
                                        infoLongPress:
                                            ledger_secure_sdk_sys::nbgl_contentInfoLongPress_t {
                                                text: self.alloc_cstring(Some(text))?,
                                                icon: core::ptr::null(),
                                                longPressText: self
                                                    .alloc_cstring(Some(long_press_text))?,
                                                longPressToken: 0, // TODO,
                                                tuneId: 0,
                                            },
                                    },
                            },
                        );
                    }
                };
            },
        }

        unsafe {
            ledger_secure_sdk_sys::nbgl_refresh();
        }
        Ok(())
    }

    #[cfg(any(target_os = "stax", target_os = "flex"))]
    pub fn show_step(&mut self, step: &Step) -> Result<(), CommEcallError> {
        Err(CommEcallError::UnhandledEcall)
    }

    #[cfg(not(any(target_os = "stax", target_os = "flex")))]
    pub fn show_step(&mut self, step: &Step) -> Result<(), CommEcallError> {
        match step {
            Step::TextSubtext { pos, text, subtext } => {
                self.clear_cstrings();
                self.release_handle();
                unsafe {
                    self.step_handle = sys::nbgl_stepDrawText(
                        *pos,
                        None,                  // callback (todo)
                        core::ptr::null_mut(), // ticker (todo)
                        self.alloc_cstring(Some(text))?,
                        self.alloc_cstring(Some(subtext))?,
                        0,     // style
                        false, // not modal
                    );
                }

                Ok(())
            }
            Step::CenteredInfo {
                pos,
                text,
                subtext,
                icon,
            } => {
                self.clear_cstrings();
                self.release_handle();

                unsafe {
                    self.step_handle = sys::nbgl_stepDrawCenteredInfo(
                        *pos,
                        None,                  // callback (todo)
                        core::ptr::null_mut(), // ticker (todo)
                        &mut ledger_secure_sdk_sys::nbgl_layoutCenteredInfo_t {
                            icon: match icon {
                                common::ux::Icon::None => core::ptr::null(),
                                common::ux::Icon::Success => core::ptr::null(), // only for large screen devices
                                common::ux::Icon::Failure => core::ptr::null(), // only for large screen devices
                                common::ux::Icon::Confirm => &bitmaps::VALIDATE_14PX,
                                common::ux::Icon::Reject => &bitmaps::CROSSMARK_14PX,
                            },

                            text1: self.alloc_cstring(text.as_ref())?,
                            text2: self.alloc_cstring(subtext.as_ref())?,
                            onTop: false,
                            style: 0,
                        }, // info
                        false,                 // not modal
                    );
                }

                Ok(())
            }
        }
    }
}
