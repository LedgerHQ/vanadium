use core::ffi::{c_char, c_int};
use core::mem::MaybeUninit;

use ledger_device_sdk::nbgl::NbglGlyph;
use ledger_device_sdk::sys::*;
use ledger_device_sdk::{include_gif, io::Comm};

use crate::vapp::VAppStore;

const TOKEN_UNINSTALL_VAPPS: u8 = FIRST_USER_TOKEN as u8;

/// Static strings for the UI (null-terminated)
static APP_NAME: &[u8] = b"Vanadium\0";
static TAGLINE: &[u8] = b"Unlimited power\nfor your apps\n(developer preview)\0";
static INFO_TYPE_VERSION: &[u8] = b"Version\0";
static INFO_TYPE_DEVELOPER: &[u8] = b"Developer\0";
static BAR_TEXT: &[u8] = b"Uninstall V-Apps\0";

// Version and author from Cargo.toml - need to be null-terminated at compile time
static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
static AUTHOR: &str = concat!(env!("CARGO_PKG_AUTHORS"), "\0");

/// Static strings for the confirmation dialog
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
static CONFIRM_MESSAGE: &[u8] = b"Uninstall V-Apps?\0";
#[cfg(not(any(target_os = "nanosplus", target_os = "nanox")))]
static CONFIRM_MESSAGE: &[u8] = b"Uninstall all V-Apps?\0";

static CONFIRM_SUBMESSAGE: &[u8] = b"This will uninstall all registered V-Apps.\0";
static CONFIRM_BUTTON: &[u8] = b"Uninstall\0";
static CANCEL_BUTTON: &[u8] = b"Cancel\0";
static NO_APPS_SUBMESSAGE: &[u8] = b"There are no registered V-Apps.\0";
static UNINSTALL_SUCCESS: &[u8] = b"All V-Apps\nuninstalled\0";

static BAR_TOKENS: [u8; 1] = [TOKEN_UNINSTALL_VAPPS];

#[cfg(target_os = "apex_p")]
static VANADIUM_ICON: NbglGlyph =
    NbglGlyph::from_include(include_gif!("icons/vanadium_48x48_bw.gif", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
static VANADIUM_ICON: NbglGlyph =
    NbglGlyph::from_include(include_gif!("icons/vanadium_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
static VANADIUM_ICON: NbglGlyph =
    NbglGlyph::from_include(include_gif!("icons/vanadium_14x14.gif", NBGL));

/// Get the Vanadium icon
fn get_icon() -> nbgl_icon_details_t {
    let bpp = match VANADIUM_ICON.bpp {
        1 => NBGL_BPP_1,
        2 => NBGL_BPP_2,
        4 => NBGL_BPP_4,
        _ => panic!("Invalid bpp"),
    };

    nbgl_icon_details_t {
        width: VANADIUM_ICON.width,
        height: VANADIUM_ICON.height,
        bpp,
        isFile: VANADIUM_ICON.is_file,
        bitmap: VANADIUM_ICON.bitmap.as_ptr(),
    }
}

/// Callback for the success status after uninstall
unsafe extern "C" fn show_home_callback() {
    // Return to home screen after showing success
    show_home_internal();
}

/// Callback for the confirmation choice dialog
unsafe extern "C" fn choice_callback(confirmed: bool) {
    if confirmed {
        // Uninstall all registered V-Apps
        loop {
            let count = VAppStore::count();
            if count == 0 {
                break;
            }
            VAppStore::unregister(count - 1);
        }
        // Show success status
        nbgl_useCaseStatus(
            UNINSTALL_SUCCESS.as_ptr() as *const c_char,
            true, // isSuccess = true shows checkmark
            Some(show_home_callback),
        );
    } else {
        // Return to home screen
        show_home_internal();
    }
}

/// Callback triggered by NBGL when a settings bar is clicked
unsafe extern "C" fn settings_action_callback(token: c_int, _index: u8, _page: c_int) {
    if token == TOKEN_UNINSTALL_VAPPS as c_int {
        let count = VAppStore::count();

        if count == 0 {
            nbgl_useCaseStatus(
                NO_APPS_SUBMESSAGE.as_ptr() as *const c_char,
                false, // isSuccess = false shows info icon
                Some(show_home_callback),
            );
        } else {
            // Show confirmation dialog with Uninstall/Cancel
            nbgl_useCaseChoice(
                core::ptr::null(), // No icon
                CONFIRM_MESSAGE.as_ptr() as *const c_char,
                CONFIRM_SUBMESSAGE.as_ptr() as *const c_char,
                CONFIRM_BUTTON.as_ptr() as *const c_char,
                CANCEL_BUTTON.as_ptr() as *const c_char,
                Some(choice_callback),
            );
        }
    }
}

/// Callback for quitting the app
unsafe extern "C" fn quit_callback() {
    ledger_device_sdk::exit_app(0);
}

/// Persistent storage for NBGL data structures
/// This struct holds all the data that NBGL needs to reference
/// All pointers must point to static location to survive across callbacks
/// Therefore, care needs to be taken with nested structs containing pointers
struct HomeScreenData {
    icon: nbgl_icon_details_t,
    info_types_ptrs: [*const c_char; 2],
    info_contents_ptrs: [*const c_char; 2],
    bar_texts_ptrs: [*const c_char; 1],
    info_list: nbgl_contentInfoList_t,
    content: nbgl_content_t,
    generic_contents: nbgl_genericContents_t,
}

/// Static storage for home screen data - initialized once
static mut HOME_DATA: MaybeUninit<HomeScreenData> = MaybeUninit::uninit();
static mut HOME_DATA_INIT: bool = false;

/// Initialize and get reference to home screen data
fn get_home_data() -> &'static HomeScreenData {
    unsafe {
        if !HOME_DATA_INIT {
            let data: *mut HomeScreenData = (&raw mut HOME_DATA).cast();

            (*data).icon = get_icon();

            (*data).info_types_ptrs = [
                INFO_TYPE_VERSION.as_ptr() as *const c_char,
                INFO_TYPE_DEVELOPER.as_ptr() as *const c_char,
            ];
            (*data).info_contents_ptrs = [
                VERSION.as_ptr() as *const c_char,
                AUTHOR.as_ptr() as *const c_char,
            ];
            (*data).bar_texts_ptrs = [BAR_TEXT.as_ptr() as *const c_char];

            // Get pointers to the arrays AFTER they've been written
            // This avoids pointing on items on the stack
            let info_types_ptr =
                core::ptr::addr_of!((*data).info_types_ptrs) as *const *const c_char;
            let info_contents_ptr =
                core::ptr::addr_of!((*data).info_contents_ptrs) as *const *const c_char;
            let bar_texts_ptr = core::ptr::addr_of!((*data).bar_texts_ptrs) as *const *const c_char;

            // Initialize info list
            (*data).info_list = nbgl_contentInfoList_t {
                infoTypes: info_types_ptr,
                infoContents: info_contents_ptr,
                nbInfos: 2,
                infoExtensions: core::ptr::null(),
                token: 0,
                withExtensions: false,
            };

            (*data).content = nbgl_content_t {
                type_: BARS_LIST as u8,
                content: nbgl_content_u {
                    barsList: nbgl_contentBarsList_t {
                        barTexts: bar_texts_ptr,
                        tokens: BAR_TOKENS.as_ptr(),
                        nbBars: 1,
                        tuneId: TUNE_TAP_CASUAL as u8,
                    },
                },
                contentActionCallback: Some(settings_action_callback),
            };

            let content_ptr = core::ptr::addr_of!((*data).content);
            (*data).generic_contents = nbgl_genericContents_t {
                callbackCallNeeded: false,
                __bindgen_anon_1: nbgl_genericContents_t__bindgen_ty_1 {
                    contentsList: content_ptr,
                },
                nbContents: 1,
            };

            HOME_DATA_INIT = true;
        }

        #[allow(static_mut_refs)]
        HOME_DATA.assume_init_ref()
    }
}

/// Internal function to show the home screen
fn show_home_internal() {
    let data = get_home_data();

    unsafe {
        nbgl_useCaseHomeAndSettings(
            APP_NAME.as_ptr() as *const c_char,
            &data.icon as *const nbgl_icon_details_t,
            TAGLINE.as_ptr() as *const c_char,
            INIT_HOME_PAGE as u8,
            &data.generic_contents as *const nbgl_genericContents_t,
            &data.info_list as *const nbgl_contentInfoList_t,
            core::ptr::null(),
            Some(quit_callback),
        );
    }
}

/// Shows the home and settings screen
pub fn show_home(_: &mut Comm<{ crate::COMM_BUFFER_SIZE }>) {
    show_home_internal();
}
