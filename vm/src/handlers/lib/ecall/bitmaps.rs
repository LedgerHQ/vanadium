use ledger_secure_sdk_sys::nbgl_icon_details_t;
pub trait ToIconDetails {
    fn to_icon_details(&self) -> *const nbgl_icon_details_t;
}

#[cfg(any(target_os = "stax", target_os = "flex", target_os = "apex_p"))]
mod large_screen {
    use super::*;
    use ledger_secure_sdk_sys::{nbgl_icon_details_t, NBGL_BPP_4};

    const CHECK_CIRCLE_64PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 64,
        height: 64,
        bpp: NBGL_BPP_4,
        isFile: true,
        bitmap: unsafe { &ledger_secure_sdk_sys::C_Check_Circle_64px_bitmap } as *const u8,
    };
    const DENIED_CIRCLE_64PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 64,
        height: 64,
        bpp: NBGL_BPP_4,
        isFile: true,
        bitmap: unsafe { &ledger_secure_sdk_sys::C_Denied_Circle_64px_bitmap } as *const u8,
    };

    impl ToIconDetails for common::ux::Icon {
        fn to_icon_details(&self) -> *const nbgl_icon_details_t {
            match self {
                common::ux::Icon::None => core::ptr::null(),
                common::ux::Icon::Success => &CHECK_CIRCLE_64PX,
                common::ux::Icon::Failure => &DENIED_CIRCLE_64PX,
                common::ux::Icon::Confirm => core::ptr::null(), // only for small screen devices
                common::ux::Icon::Reject => core::ptr::null(),  // only for small screen devices
                common::ux::Icon::Processing => core::ptr::null(), // only for small screen devices
            }
        }
    }
}

#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
mod small_screen {
    use super::*;
    use ledger_secure_sdk_sys::{nbgl_icon_details_t, NBGL_BPP_1};

    const VALIDATE_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: true,
        bitmap: unsafe { &ledger_secure_sdk_sys::C_icon_validate_14_bitmap } as *const u8,
    };

    const CROSSMARK_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: false,
        bitmap: unsafe { &ledger_secure_sdk_sys::C_icon_crossmark_bitmap } as *const u8,
    };

    const PROCESSING_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: false,
        bitmap: unsafe { &ledger_secure_sdk_sys::C_icon_processing_bitmap } as *const u8,
    };

    impl ToIconDetails for common::ux::Icon {
        fn to_icon_details(&self) -> *const nbgl_icon_details_t {
            match self {
                common::ux::Icon::None => core::ptr::null(),
                common::ux::Icon::Success => core::ptr::null(), // only for large screen devices
                common::ux::Icon::Failure => core::ptr::null(), // only for large screen devices
                common::ux::Icon::Confirm => &VALIDATE_14PX,
                common::ux::Icon::Reject => &CROSSMARK_14PX,
                common::ux::Icon::Processing => &PROCESSING_14PX,
            }
        }
    }
}
