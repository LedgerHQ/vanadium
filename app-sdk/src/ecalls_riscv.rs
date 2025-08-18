#![allow(unused_macros)]

use common::ux::EventData;

macro_rules! delegate_ecall {
    ($name:ident $(, ($arg_name:ident: $arg_type:ty))*) => {
        pub fn $name($($arg_name: $arg_type),*) {
            unsafe { vanadium_ecalls::$name($($arg_name),*) }
        }
    };
    ($name:ident, $ret:ty $(, ($arg_name:ident: $arg_type:ty))*) => {
        pub fn $name($($arg_name: $arg_type),*) -> $ret {
            unsafe { vanadium_ecalls::$name($($arg_name),*) }
        }
    };
}

delegate_ecall!(exit, !, (status: i32));
delegate_ecall!(fatal, !, (msg: *const u8), (size: usize));
delegate_ecall!(xsend, (buffer: *const u8), (size: usize));
delegate_ecall!(xrecv, usize, (buffer: *mut u8), (size: usize));
delegate_ecall!(print, (buffer: *const u8), (size: usize));

delegate_ecall!(get_event, u32, (data: *mut EventData));
delegate_ecall!(show_page, u32, (page_desc: *const u8), (page_desc_len: usize));
delegate_ecall!(show_step, u32, (step_desc: *const u8), (step_desc_len: usize));
delegate_ecall!(get_device_property, u32, (property: u32));

delegate_ecall!(bn_modm, u32, (r: *mut u8), (n: *const u8), (len: usize), (m: *const u8), (len_m: usize));
delegate_ecall!(bn_addm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
delegate_ecall!(bn_subm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
delegate_ecall!(bn_multm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
delegate_ecall!(bn_powm, u32, (r: *mut u8), (a: *const u8), (e: *const u8), (len_e: usize), (m: *const u8), (len: usize));

delegate_ecall!(derive_hd_node, u32, (curve: u32), (path: *const u32), (path_len: usize), (privkey: *mut u8), (chain_code: *mut u8));
delegate_ecall!(get_master_fingerprint, u32, (curve: u32));
delegate_ecall!(derive_slip21_node, u32, (label: *const u8), (label_len: usize), (out: *mut u8));

delegate_ecall!(ecfp_add_point, u32, (curve: u32), (r: *mut u8), (p: *const u8), (q: *const u8));
delegate_ecall!(ecfp_scalar_mult, u32, (curve: u32), (r: *mut u8), (p: *const u8), (k: *const u8), (k_len: usize));

delegate_ecall!(get_random_bytes, u32, (buffer: *mut u8), (size: usize));

delegate_ecall!(ecdsa_sign, usize, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg_hash: *const u8), (signature: *mut u8));
delegate_ecall!(ecdsa_verify, u32, (curve: u32), (pubkey: *const u8), (msg_hash: *const u8), (signature: *const u8), (signature_len: usize));
delegate_ecall!(schnorr_sign, usize, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *mut u8), (entropy: *const [u8; 32]));
delegate_ecall!(schnorr_verify, u32, (curve: u32), (mode: u32), (hash_id: u32), (pubkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *const u8), (signature_len: usize));

// The following ecalls are specific to this target
delegate_ecall!(hash_init, (hash_id: u32), (ctx: *mut u8));
delegate_ecall!(hash_update, u32, (hash_id: u32), (ctx: *mut u8), (data: *const u8), (len: usize));
delegate_ecall!(hash_final, u32, (hash_id: u32), (ctx: *mut u8), (digest: *const u8));
