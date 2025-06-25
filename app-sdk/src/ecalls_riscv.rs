#![allow(unused_macros)]

use crate::ecalls::EcallsInterface;
use common::ux::EventData;

macro_rules! delegate_ecall {
    ($vis:vis $name:ident $(, ($arg_name:ident: $arg_type:ty))*) => {
        $vis fn $name($($arg_name: $arg_type),*) {
            unsafe { vanadium_ecalls::$name($($arg_name),*) }
        }
    };
    ($vis:vis $name:ident, $ret:ty $(, ($arg_name:ident: $arg_type:ty))*) => {
        $vis fn $name($($arg_name: $arg_type),*) -> $ret {
            unsafe { vanadium_ecalls::$name($($arg_name),*) }
        }
    };
}

pub struct Ecall;

impl EcallsInterface for Ecall {
    delegate_ecall!(exit, !, (status: i32));
    delegate_ecall!(fatal, !, (msg: *const u8), (size: usize));
    delegate_ecall!(xsend, (buffer: *const u8), (size: usize));
    delegate_ecall!(xrecv, usize, (buffer: *mut u8), (size: usize));

    delegate_ecall!(get_event, u32, (data: *mut EventData));
    delegate_ecall!(show_page, u32, (page_desc: *const u8), (page_desc_len: usize));

    delegate_ecall!(bn_modm, u32, (r: *mut u8), (n: *const u8), (len: usize), (m: *const u8), (len_m: usize));
    delegate_ecall!(bn_addm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
    delegate_ecall!(bn_subm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
    delegate_ecall!(bn_multm, u32, (r: *mut u8), (a: *const u8), (b: *const u8), (m: *const u8), (len: usize));
    delegate_ecall!(bn_powm, u32, (r: *mut u8), (a: *const u8), (e: *const u8), (len_e: usize), (m: *const u8), (len: usize));

    delegate_ecall!(derive_hd_node, u32, (curve: u32), (path: *const u32), (path_len: usize), (privkey: *mut u8), (chain_code: *mut u8));
    delegate_ecall!(get_master_fingerprint, u32, (curve: u32));

    delegate_ecall!(ecfp_add_point, u32, (curve: u32), (r: *mut u8), (p: *const u8), (q: *const u8));
    delegate_ecall!(ecfp_scalar_mult, u32, (curve: u32), (r: *mut u8), (p: *const u8), (k: *const u8), (k_len: usize));

    delegate_ecall!(get_random_bytes, u32, (buffer: *mut u8), (size: usize));

    delegate_ecall!(ecdsa_sign, usize, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg_hash: *const u8), (signature: *mut u8));
    delegate_ecall!(ecdsa_verify, u32, (curve: u32), (pubkey: *const u8), (msg_hash: *const u8), (signature: *const u8), (signature_len: usize));
    delegate_ecall!(schnorr_sign, usize, (curve: u32), (mode: u32), (hash_id: u32), (privkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *mut u8), (entropy: *const [u8; 32]));
    delegate_ecall!(schnorr_verify, u32, (curve: u32), (mode: u32), (hash_id: u32), (pubkey: *const u8), (msg: *const u8), (msg_len: usize), (signature: *const u8), (signature_len: usize));
}

impl Ecall {
    // The following ecalls are specific to this target
    delegate_ecall!(pub hash_init, (hash_id: u32), (ctx: *mut u8));
    delegate_ecall!(pub hash_update, u32, (hash_id: u32), (ctx: *mut u8), (data: *const u8), (len: usize));
    delegate_ecall!(pub hash_final, u32, (hash_id: u32), (ctx: *mut u8), (digest: *const u8));
}

