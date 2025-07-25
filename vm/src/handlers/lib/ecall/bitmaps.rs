use ledger_secure_sdk_sys::nbgl_icon_details_t;
pub trait ToIconDetails {
    fn to_icon_details(&self) -> *const nbgl_icon_details_t;
}

#[cfg(any(target_os = "stax", target_os = "flex"))]
mod large_screen {
    use super::*;
    use ledger_secure_sdk_sys::{nbgl_icon_details_t, NBGL_BPP_4};

    const CHECK_CIRCLE_64PX_BITMAP: [u8; 571] = [
        0x40, 0x00, 0x40, 0x00, 0x21, 0x33, 0x02, 0x00, 0x31, 0x02, 0x1f, 0x8b, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0xff, 0xad, 0x55, 0x39, 0x4e, 0x03, 0x31, 0x14, 0xfd, 0x24, 0x61,
        0x5f, 0x4b, 0x28, 0x80, 0x91, 0xa0, 0x01, 0x24, 0x88, 0xb8, 0x40, 0x46, 0x54, 0x20, 0x21,
        0x41, 0x49, 0x39, 0x2d, 0x15, 0xdc, 0x00, 0x90, 0xa0, 0x66, 0x11, 0xa2, 0x05, 0x71, 0x01,
        0x10, 0x17, 0x48, 0x0a, 0x6a, 0x02, 0x17, 0x60, 0xab, 0x41, 0x61, 0x89, 0x04, 0x24, 0x21,
        0x9f, 0xef, 0x65, 0x66, 0xbe, 0x3d, 0x0e, 0x8b, 0xc4, 0x14, 0x99, 0xb1, 0x9f, 0xfd, 0xfc,
        0xfc, 0xfc, 0xf3, 0x8c, 0xf8, 0x7f, 0x4f, 0xf5, 0x60, 0x1a, 0x60, 0x74, 0xa9, 0xd8, 0x00,
        0xde, 0x04, 0xfd, 0xcc, 0x95, 0x1c, 0x68, 0xcd, 0x87, 0xe8, 0xc9, 0x14, 0xbf, 0x85, 0x01,
        0x52, 0x79, 0x0b, 0xae, 0x1b, 0x30, 0x40, 0x8b, 0xb5, 0xc4, 0xae, 0x9c, 0xb5, 0x7c, 0x8d,
        0xf8, 0x70, 0xe0, 0x89, 0xef, 0x71, 0x03, 0x7e, 0x13, 0x5d, 0xfd, 0x7a, 0x4e, 0x7d, 0x4f,
        0xb4, 0xd6, 0x38, 0x9e, 0xa5, 0x8e, 0xf9, 0xb8, 0x79, 0x4c, 0xcd, 0x34, 0x5b, 0xe1, 0x9e,
        0xda, 0x13, 0x7c, 0xbc, 0x18, 0x30, 0x19, 0x8b, 0xa3, 0x15, 0x5b, 0x4d, 0xb9, 0x01, 0xa9,
        0x89, 0x5a, 0xaf, 0x34, 0xfa, 0xd0, 0xd4, 0xfb, 0x41, 0x5d, 0xb9, 0xb0, 0xb1, 0x0a, 0x30,
        0x68, 0xfb, 0x71, 0x15, 0x53, 0x56, 0x00, 0x9a, 0x6e, 0x6c, 0xfc, 0xb3, 0x2f, 0xe2, 0x24,
        0x75, 0xdd, 0x49, 0xbf, 0x2f, 0x01, 0x86, 0xd4, 0x57, 0x10, 0x8e, 0xac, 0x5a, 0x0a, 0x32,
        0xaa, 0x97, 0xdc, 0x54, 0x5d, 0x47, 0x39, 0x3e, 0x80, 0x54, 0xc9, 0x63, 0x7a, 0x09, 0xb7,
        0x5a, 0x81, 0x34, 0xc7, 0xa9, 0x7f, 0x41, 0xbc, 0x0b, 0x00, 0x27, 0x6a, 0x3a, 0xdb, 0x92,
        0xe2, 0xed, 0x12, 0x6f, 0x3f, 0x74, 0x82, 0xb6, 0x64, 0x10, 0xf8, 0x52, 0x40, 0x1d, 0xa0,
        0x23, 0xde, 0x12, 0x27, 0x20, 0x62, 0xa5, 0x73, 0x0a, 0x9d, 0x04, 0xcf, 0x00, 0xdb, 0x88,
        0xe5, 0xd8, 0x5b, 0x8b, 0xe0, 0x5d, 0x0a, 0x7c, 0x02, 0x28, 0xa1, 0x93, 0x80, 0x56, 0xee,
        0x15, 0xab, 0xa4, 0x0c, 0x53, 0x19, 0x81, 0x07, 0x9d, 0x88, 0xeb, 0xa1, 0x3b, 0x49, 0x82,
        0x00, 0xda, 0x11, 0x17, 0xc5, 0x8f, 0x9b, 0x60, 0x47, 0x4c, 0xf5, 0x95, 0x0b, 0x2e, 0x82,
        0x4b, 0xf1, 0xed, 0x41, 0x0f, 0x36, 0x20, 0xb8, 0x15, 0xd2, 0xa4, 0x48, 0x37, 0xc1, 0x93,
        0x30, 0xc8, 0xc2, 0x39, 0x81, 0x0b, 0xe7, 0x04, 0x4e, 0x5c, 0x10, 0xac, 0x30, 0xdc, 0xd4,
        0xa7, 0x08, 0x56, 0x98, 0xbe, 0xac, 0x5d, 0x7c, 0x31, 0x5e, 0x10, 0x07, 0x1c, 0x70, 0x7f,
        0x34, 0xff, 0x5a, 0xe8, 0x4f, 0xb3, 0x36, 0xc9, 0xad, 0x2f, 0x80, 0x36, 0xc4, 0x53, 0x76,
        0x3e, 0xd6, 0xfe, 0x3c, 0x61, 0x2d, 0x3f, 0x5f, 0x73, 0xba, 0x3a, 0xdf, 0xb2, 0xac, 0x12,
        0xd7, 0xf4, 0x0f, 0x59, 0x1f, 0x54, 0x25, 0xc3, 0x6e, 0x7b, 0x5f, 0x54, 0x65, 0x01, 0x3b,
        0x40, 0xe3, 0x78, 0x8e, 0xd4, 0xca, 0xbe, 0xfe, 0x1f, 0xe9, 0x92, 0x4c, 0xb3, 0xf2, 0xc9,
        0xe8, 0x32, 0xce, 0xb3, 0x92, 0x8c, 0xa6, 0x57, 0x34, 0x71, 0x39, 0x2e, 0x70, 0xaa, 0xb6,
        0x34, 0x0f, 0x1d, 0xd9, 0x5f, 0xe3, 0xe1, 0xf2, 0x9e, 0x63, 0xd5, 0xa7, 0x79, 0xfd, 0x44,
        0xba, 0xe8, 0xdd, 0x69, 0x63, 0xef, 0x1a, 0xe5, 0xc3, 0x64, 0x34, 0xd2, 0x9d, 0x2f, 0x27,
        0xbf, 0xcb, 0xa7, 0x1f, 0xf3, 0x8d, 0x9c, 0xb0, 0x03, 0x9b, 0x28, 0x53, 0x25, 0x23, 0x5f,
        0x8d, 0xc0, 0x3e, 0x33, 0xf2, 0x15, 0xeb, 0x59, 0x73, 0xc0, 0x39, 0x58, 0x51, 0x22, 0xf3,
        0x7d, 0x2c, 0xcc, 0xf7, 0x8d, 0x44, 0xbe, 0xcb, 0xc0, 0xa6, 0xfb, 0xe1, 0x02, 0xf1, 0x51,
        0xdd, 0x0f, 0x03, 0x98, 0x08, 0x6c, 0xfe, 0x64, 0xec, 0x2b, 0xac, 0xea, 0x19, 0x70, 0xf1,
        0xaf, 0xf7, 0x1b, 0x2d, 0xb1, 0x1f, 0xc2, 0xb3, 0x0d, 0x2e, 0xd0, 0xda, 0xd6, 0x0c, 0xc0,
        0xc8, 0x72, 0xfe, 0x1f, 0xaf, 0x6c, 0xfc, 0x02, 0x24, 0x14, 0x5a, 0xc5, 0x00, 0x08, 0x00,
        0x00,
    ];
    const CHECK_CIRCLE_64PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 64,
        height: 64,
        bpp: NBGL_BPP_4,
        isFile: true,
        bitmap: &CHECK_CIRCLE_64PX_BITMAP as *const u8,
    };

    const DENIED_CIRCLE_64PX_BITMAP: [u8; 568] = [
        0x40, 0x00, 0x40, 0x00, 0x21, 0x30, 0x02, 0x00, 0x2e, 0x02, 0x1f, 0x8b, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0xff, 0xad, 0x55, 0x4b, 0x2f, 0x04, 0x41, 0x10, 0x2e, 0x6b, 0xbd,
        0x9f, 0x47, 0x0e, 0xd8, 0x84, 0x48, 0x90, 0xac, 0x8d, 0x3f, 0x60, 0xe2, 0x44, 0x22, 0xe1,
        0xe8, 0xb8, 0x71, 0x73, 0xe2, 0x1f, 0x20, 0xe1, 0xec, 0x11, 0x71, 0x25, 0xfe, 0x00, 0xf1,
        0x07, 0xd6, 0xc1, 0xd9, 0xf2, 0x07, 0x3c, 0xe6, 0x4c, 0xd6, 0x63, 0xe3, 0xb9, 0xa6, 0x54,
        0xf5, 0x63, 0xa6, 0xa7, 0x67, 0x66, 0x97, 0x44, 0x1f, 0x76, 0xb6, 0xbb, 0xba, 0xaa, 0xbe,
        0xfe, 0xea, 0xeb, 0x6a, 0xc4, 0xff, 0x1b, 0x5f, 0xfb, 0x13, 0x00, 0x43, 0x0b, 0xc5, 0x04,
        0xf3, 0x06, 0xa8, 0x31, 0x53, 0x8a, 0xb1, 0x56, 0x1c, 0xf0, 0x47, 0xba, 0x58, 0xd5, 0x0c,
        0x90, 0x2a, 0x58, 0x66, 0x2f, 0x64, 0x06, 0x68, 0xb4, 0x52, 0xec, 0x08, 0xaf, 0xa5, 0x6b,
        0xc4, 0xfb, 0xfd, 0x0c, 0xff, 0x1f, 0x0d, 0x99, 0xdf, 0x78, 0xa9, 0x47, 0xf9, 0x78, 0xbb,
        0x3c, 0x5b, 0x35, 0xed, 0x39, 0x5a, 0x98, 0x0d, 0xa6, 0x47, 0x34, 0xad, 0x37, 0x32, 0xb8,
        0x34, 0x1f, 0x33, 0xf7, 0xf3, 0x86, 0x6c, 0x00, 0x8e, 0x32, 0x36, 0x85, 0xe1, 0xe6, 0x09,
        0x8d, 0x3f, 0x7b, 0xa1, 0xdd, 0x07, 0x61, 0xbc, 0x1f, 0xb4, 0x34, 0xa9, 0x27, 0x2b, 0x00,
        0x7d, 0x36, 0x1f, 0x57, 0x41, 0xc8, 0x4f, 0x80, 0xba, 0x1b, 0xdb, 0xfe, 0xdd, 0xed, 0xc7,
        0x24, 0x74, 0x1d, 0x51, 0xbe, 0x2f, 0x01, 0xfa, 0xe5, 0xbf, 0x7c, 0x24, 0xbb, 0x42, 0x90,
        0x96, 0x55, 0x25, 0x36, 0xe3, 0xca, 0x49, 0xa8, 0x44, 0x99, 0x9e, 0xcd, 0xa3, 0x1a, 0x83,
        0xd6, 0xe7, 0xf8, 0x7b, 0x06, 0x70, 0x2c, 0x0f, 0x6d, 0xa9, 0x05, 0xa0, 0x9d, 0xbf, 0x8e,
        0x66, 0x62, 0x51, 0xf3, 0x3f, 0x2c, 0xbf, 0x8e, 0x00, 0xe0, 0x01, 0xb4, 0x8a, 0xe9, 0xab,
        0x4e, 0xe3, 0xc2, 0x32, 0xaa, 0xc0, 0x12, 0xe7, 0xb8, 0x3a, 0x46, 0xaa, 0xa4, 0xd8, 0x96,
        0x78, 0x9f, 0x00, 0xb6, 0x10, 0xcb, 0xfa, 0x74, 0x19, 0x85, 0x93, 0xe8, 0x90, 0x1b, 0xdf,
        0x05, 0xc0, 0x47, 0x80, 0x12, 0x1a, 0xeb, 0x9e, 0xde, 0xc7, 0x99, 0xbb, 0x38, 0x4b, 0x2a,
        0xa8, 0x62, 0xd6, 0x70, 0xe7, 0x88, 0x6d, 0x88, 0x6b, 0x3e, 0x3b, 0xc2, 0x12, 0xb8, 0x33,
        0xa2, 0x16, 0xc4, 0x79, 0xfe, 0x09, 0x02, 0x18, 0xee, 0xb8, 0xcd, 0xae, 0x8e, 0x64, 0x41,
        0x07, 0x30, 0xdc, 0xa9, 0x44, 0xf5, 0x9c, 0xa4, 0xd3, 0xd4, 0x91, 0xe1, 0x8e, 0xb7, 0x0c,
        0x4d, 0x80, 0x34, 0x74, 0x68, 0x14, 0xe3, 0x91, 0x09, 0x32, 0xed, 0x1c, 0x20, 0x70, 0xff,
        0xbb, 0x3d, 0x2e, 0x7e, 0x2d, 0x7c, 0xb9, 0x40, 0x7c, 0xf6, 0xf9, 0xce, 0xb8, 0xc0, 0xf9,
        0x6a, 0xfc, 0x34, 0x28, 0x92, 0x92, 0xf8, 0x6d, 0x46, 0x3c, 0xa9, 0x56, 0x9f, 0xf6, 0xda,
        0xf5, 0x2d, 0x0b, 0x95, 0x18, 0xeb, 0xae, 0xbe, 0x9a, 0x1f, 0x42, 0x1f, 0xa4, 0x92, 0x81,
        0x78, 0x7d, 0x3d, 0x4b, 0x65, 0x29, 0x19, 0x47, 0xf5, 0x79, 0x28, 0x33, 0x3b, 0xea, 0x1e,
        0x45, 0xf4, 0x9d, 0x91, 0x06, 0x92, 0xb1, 0xd5, 0xcd, 0x4a, 0xfa, 0x5a, 0x8b, 0xc0, 0x65,
        0x2d, 0x70, 0x6b, 0xb8, 0x6a, 0xbd, 0x62, 0x37, 0x17, 0x9f, 0x1d, 0x15, 0xd7, 0x49, 0xba,
        0xdf, 0x8a, 0xd8, 0xbb, 0xa4, 0xfe, 0x90, 0xf5, 0x77, 0xc6, 0xf7, 0x97, 0xe3, 0xdf, 0xf5,
        0xa7, 0x9a, 0xfd, 0x8d, 0xaf, 0xa6, 0xd5, 0xb0, 0x57, 0x42, 0x42, 0x74, 0xed, 0x86, 0x7d,
        0x1a, 0xd2, 0x21, 0x7a, 0xb9, 0xf0, 0x86, 0x73, 0xee, 0xcf, 0x91, 0xfe, 0x3e, 0xa2, 0xf9,
        0x5f, 0x8f, 0xf4, 0x77, 0xd1, 0xb0, 0xe9, 0x7d, 0xb8, 0x40, 0x7c, 0x90, 0xef, 0x43, 0x2f,
        0x46, 0x1a, 0xb6, 0x39, 0xd2, 0xf6, 0x13, 0xf6, 0x95, 0x09, 0x99, 0x8b, 0x7f, 0x7d, 0xdf,
        0x28, 0xc5, 0x9e, 0x36, 0x4f, 0x27, 0x3c, 0xa0, 0x95, 0xcd, 0x29, 0x80, 0xc1, 0xa5, 0xc2,
        0x3f, 0x3e, 0xd9, 0xf8, 0x03, 0x70, 0xa7, 0x85, 0x84, 0x00, 0x08, 0x00, 0x00,
    ];

    const DENIED_CIRCLE_64PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 64,
        height: 64,
        bpp: NBGL_BPP_4,
        isFile: true,
        bitmap: &DENIED_CIRCLE_64PX_BITMAP as *const u8,
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

#[cfg(not(any(target_os = "stax", target_os = "flex")))]
mod small_screen {
    use super::*;
    use ledger_secure_sdk_sys::{nbgl_icon_details_t, NBGL_BPP_1};

    const VALIDATE_14X14_BITMAP: [u8; 23] = [
        0x0e, 0x00, 0x0e, 0x00, 0x02, 0x0f, 0x00, 0x00, 0x32, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3,
        0xc3, 0xb3, 0xa3, 0xa3, 0xa3, 0xb2, 0xf0, 0x50,
    ];
    const VALIDATE_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: true,
        bitmap: &VALIDATE_14X14_BITMAP as *const u8,
    };

    const CROSSMARK_14X14_BITMAP: [u8; 25] = [
        0x00, 0x01, 0x80, 0x67, 0x03, 0x8e, 0x1c, 0x1c, 0xe0, 0x3f, 0x00, 0x78, 0x01, 0xe0, 0x0f,
        0xc0, 0x73, 0x83, 0x87, 0x1c, 0x0e, 0x60, 0x18, 0x00, 0x00,
    ];

    const CROSSMARK_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: false,
        bitmap: &CROSSMARK_14X14_BITMAP as *const u8,
    };

    const PROCESSING_14X14_BITMAP: [u8; 25] = [
        0x00, 0x00, 0x0c, 0x01, 0x32, 0x0e, 0xdc, 0x18, 0x60, 0x00, 0x07, 0x03, 0x9c, 0x0e, 0x00,
        0x00, 0x61, 0x83, 0xb7, 0x04, 0xc8, 0x03, 0x00, 0x00, 0x00,
    ];
    const PROCESSING_14PX: nbgl_icon_details_t = nbgl_icon_details_t {
        width: 14,
        height: 14,
        bpp: NBGL_BPP_1,
        isFile: false,
        bitmap: &PROCESSING_14X14_BITMAP as *const u8,
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
