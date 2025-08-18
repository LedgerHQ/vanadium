#![allow(unused_macros)]

use common::ecall_constants::*;
use common::ux::EventData;
use core::arch::asm;

macro_rules! ecall0v {
    // ECALL with no arguments and no return value
    ($fn_name:ident, $syscall_number:expr) => {
        pub unsafe fn $fn_name() {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                );
            }
        }
    };
}
macro_rules! ecall0 {
    // ECALL with no arguments and returning a value
    ($fn_name:ident, $syscall_number:expr, $ret_type:ty) => {
        pub unsafe fn $fn_name() -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall1v {
    // ECALL with 1 argument and no return value
    ($fn_name:ident, $syscall_number:expr, ($arg1:ident: $arg1_type:ty)) => {
        pub unsafe fn $fn_name($arg1: $arg1_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1             // First argument in a0
                );
            }
        }
    };
}
macro_rules! ecall1 {
    // ECALL with 1 argument and returning a value
    ($fn_name:ident, $syscall_number:expr, ($arg1:ident: $arg1_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall2v {
    // ECALL with 2 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty)) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2             // Second argument in a1
                );
            }
        }
    };
}
macro_rules! ecall2 {
    // ECALL with 2 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}
macro_rules! ecall3v {
    // ECALL with 3 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty)) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3             // Third argument in a2
                );
            }
        }
    };
}
macro_rules! ecall3 {
    // ECALL with 3 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall4v {
    // ECALL with 4 arguments and no return value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty)) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type) {
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4             // Fourth argument in a3
                );
            }
        }
    };
}
macro_rules! ecall4 {
    // ECALL with 4 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Fourth argument in a3
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall5 {
    // ECALL with 5 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Third argument in a3
                    in("a4") $arg5,            // Third argument in a4
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall6 {
    // ECALL with 6 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty),
     ($arg6:ident: $arg6_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type, $arg6: $arg6_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Third argument in a3
                    in("a4") $arg5,            // Third argument in a4
                    in("a5") $arg6,            // Third argument in a5
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall7 {
    // ECALL with 7 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty),
     ($arg6:ident: $arg6_type:ty),
     ($arg7:ident: $arg7_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type, $arg6: $arg6_type, $arg7: $arg7_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Fourth argument in a3
                    in("a4") $arg5,            // Fifth argument in a4
                    in("a5") $arg6,            // Sixth argument in a5
                    in("a6") $arg7,            // Seventh argument in a6
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

macro_rules! ecall8 {
    // ECALL with 8 arguments and returning a value
    ($fn_name:ident, $syscall_number:expr,
     ($arg1:ident: $arg1_type:ty),
     ($arg2:ident: $arg2_type:ty),
     ($arg3:ident: $arg3_type:ty),
     ($arg4:ident: $arg4_type:ty),
     ($arg5:ident: $arg5_type:ty),
     ($arg6:ident: $arg6_type:ty),
     ($arg7:ident: $arg7_type:ty),
     ($arg8:ident: $arg8_type:ty), $ret_type:ty) => {
        pub unsafe fn $fn_name($arg1: $arg1_type, $arg2: $arg2_type, $arg3: $arg3_type, $arg4: $arg4_type, $arg5: $arg5_type, $arg6: $arg6_type, $arg7: $arg7_type, $arg8: $arg8_type) -> $ret_type {
            let ret: $ret_type;
            unsafe {
                asm!(
                    "ecall",
                    in("t0") $syscall_number,  // Pass the syscall number in t0
                    in("a0") $arg1,            // First argument in a0
                    in("a1") $arg2,            // Second argument in a1
                    in("a2") $arg3,            // Third argument in a2
                    in("a3") $arg4,            // Fourth argument in a3
                    in("a4") $arg5,            // Fifth argument in a4
                    in("a5") $arg6,            // Sixth argument in a5
                    in("a6") $arg7,            // Seventh argument in a6
                    in("a7") $arg8,            // Eighth argument in a7
                    lateout("a0") ret          // Return value in a0
                );
            }
            ret
        }
    };
}

// fatal() and exit() are diverging, therefore we can't use the macro
pub unsafe fn exit(status: i32) -> ! {
    unsafe {
        asm!(
            "ecall",
            in("t0") ECALL_EXIT,
            in("a0") status,
            options(noreturn)
        );
    }
}

pub unsafe fn fatal(msg: *const u8, size: usize) -> ! {
    unsafe {
        asm!(
            "ecall",
            in("t0") ECALL_FATAL,
            in("a0") msg,
            in("a1") size,
            options(noreturn)
        );
    }
}

ecall2v!(xsend, ECALL_XSEND, (buffer: *const u8), (size: usize));
ecall2!(xrecv, ECALL_XRECV, (buffer: *mut u8), (size: usize), usize);
ecall2v!(print, ECALL_PRINT, (buffer: *const u8), (size: usize));

ecall1!(get_event, ECALL_GET_EVENT, (data: *mut EventData), u32);
ecall2!(show_page, ECALL_SHOW_PAGE, (page_desc: *const u8), (page_desc_len: usize), u32);
ecall2!(show_step, ECALL_SHOW_STEP, (step_desc: *const u8), (step_desc_len: usize), u32);
ecall1!(get_device_property, ECALL_GET_DEVICE_PROPERTY, (property: u32), u32);

ecall5!(bn_modm, ECALL_MODM, (r: *mut u8), (n: *const u8), (len: usize), (m: *const u8), (len_m: usize), u32);
ecall5!(bn_addm, ECALL_ADDM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
ecall5!(bn_subm, ECALL_SUBM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
ecall5!(bn_multm, ECALL_MULTM, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize), u32);
ecall6!(bn_powm, ECALL_POWM, (r: *mut u8), (a: *const u8), (e: *const u8), (len_e: usize), (m: *const u8), (len: usize), u32);

ecall5!(derive_hd_node, ECALL_DERIVE_HD_NODE, (curve: u32), (path: *const u32), (path_len: usize), (privkey: *mut u8), (chain_code: *mut u8), u32);
ecall1!(get_master_fingerprint, ECALL_GET_MASTER_FINGERPRINT, (curve: u32), u32);
ecall3!(derive_slip21_node, ECALL_DERIVE_SLIP21_KEY, (labels: *const u8), (labels_len: usize), (out: *mut u8), u32);

ecall4!(ecfp_add_point, ECALL_ECFP_ADD_POINT, (curve: u32), (r: *mut u8), (p: *const u8), (q: *const u8), u32);
ecall5!(ecfp_scalar_mult, ECALL_ECFP_SCALAR_MULT, (curve: u32), (r: *mut u8), (p: *const u8), (k: *const u8), (k_len: usize), u32);

ecall2!(get_random_bytes, ECALL_GET_RANDOM_BYTES, (buffer: *mut u8), (size: usize), u32);

ecall6!(ecdsa_sign, ECALL_ECDSA_SIGN, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg_hash: *const u8), (signature: *mut u8), usize);
ecall5!(ecdsa_verify, ECALL_ECDSA_VERIFY, (curve: u32), (pubkey: *const u8), (msg_hash: *const u8), (signature: *const u8), (signature_len: usize), u32);
ecall8!(schnorr_sign, ECALL_SCHNORR_SIGN, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *mut u8), (entropy: *const [u8; 32]), usize);
ecall8!(schnorr_verify, ECALL_SCHNORR_VERIFY, (curve: u32), (mode: u32), (hash_id: u32), (pubkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *const u8), (signature_len: usize), u32);

// The following ecalls are specific to this target
ecall2v!(hash_init, ECALL_HASH_INIT, (hash_id: u32), (ctx: *mut u8));
ecall4!(hash_update, ECALL_HASH_UPDATE, (hash_id: u32), (ctx: *mut u8), (data: *const u8), (len: usize), u32);
ecall3!(hash_final, ECALL_HASH_DIGEST, (hash_id: u32), (ctx: *mut u8), (digest: *const u8), u32);
