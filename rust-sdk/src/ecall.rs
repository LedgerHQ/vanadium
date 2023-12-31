use crate::crypto::{CtxHashGuest, CxCurve, CxHashId, CxMd, EcfpPrivateKey, EcfpPublicKey};
use crate::ux::BaglComponent;

#[repr(C)]
pub enum FormatConversion {
    BASE58ENCODE = 0,
    BASE58DECODE = 1,
    SEGWITADDRMAINNET = 2,
    SEGWITADDRTESTNET = 3,
}

extern "C" {
    pub fn ecall_app_loading_start(status: *const u8);
    pub fn ecall_app_loading_stop() -> bool;
    pub fn ecall_bagl_hal_draw_bitmap_within_rect(
        x: i32,
        y: i32,
        width: usize,
        height: usize,
        colors: *const u32,
        bpp: usize,
        bitmap: *const u8,
        bitmap_length_bits: usize,
    );
    pub fn ecall_bagl_draw_with_context(
        component: &BaglComponent,
        context: *const u8,
        context_length: u16,
        context_encoding: u8,
    );
    pub fn ecall_fatal(msg: *const u8, size: usize);
    pub fn ecall_screen_update();
    pub fn ecall_ux_idle();
    pub fn ecall_xrecv(buffer: *mut u8, size: usize) -> usize;
    pub fn ecall_xsend(buffer: *const u8, size: usize);
    pub fn ecall_wait_button() -> u32;

    pub fn ecall_cx_ecfp_generate_pair(
        curve: CxCurve,
        pubkey: &mut EcfpPublicKey,
        privkey: &mut EcfpPrivateKey,
        keep_privkey: bool,
    ) -> bool;
    pub fn ecall_cx_ecfp_add_point(
        curve: CxCurve,
        r: *mut u8,
        p: *const u8,
        q: *const u8,
    ) -> bool;
    pub fn ecall_cx_ecfp_scalar_mult(
        curve: CxCurve,
        p: *mut u8,
        k: *const u8,
        k_len: usize,
    ) -> bool;
    pub fn ecall_derive_node_bip32(
        curve: CxCurve,
        path: *const u32,
        path_count: usize,
        privkey_data: *mut u8,
        chain_code: *mut u8,
    ) -> bool;
    pub fn ecall_ecdsa_sign(
        key: &EcfpPrivateKey,
        mode: i32,
        hash_id: CxMd,
        hash: *const u8,
        sig: *mut u8,
        sig_len: usize,
        parity: *mut i32) -> usize;
    pub fn ecall_ecdsa_verify(
        key: &EcfpPublicKey,
        hash: *const u8,
        sig: *const u8,
        sig_len: usize,
    ) -> bool;
    pub fn ecall_schnorr_sign(
        key: &EcfpPrivateKey,
        mode: u32,
        hash_id: CxMd,
        msg: *const u8,
        msg_len: usize,
        sig: *mut u8,
        sig_len: *mut usize) -> bool;
    pub fn ecall_schnorr_verify(
        key: &EcfpPublicKey,
        mode: u32,
        hash_id: CxMd,
        msg: *const u8,
        msg_len: usize,
        sig: *const u8,
        sig_len: usize) -> bool;
    pub fn ecall_get_random_bytes(buffer: *mut u8, size: usize);
    pub fn ecall_hash_update(
        hash_id: CxHashId,
        ctx: CtxHashGuest,
        buffer: *const u8,
        size: usize,
    ) -> bool;
    pub fn ecall_hash_final(hash_id: CxHashId, ctx: CtxHashGuest, buffer: *mut u8) -> bool;
    pub fn ecall_get_master_fingerprint(out: *mut [u8; 4]) -> bool;

    pub fn ecall_addm(
        r: *mut u8,
        a: *const u8,
        b: *const u8,
        m: *const u8,
        len: usize,
    ) -> bool;

    pub fn ecall_subm(
        r: *mut u8,
        a: *const u8,
        b: *const u8,
        m: *const u8,
        len: usize,
    ) -> bool;

    pub fn ecall_multm(
        r: *mut u8,
        a: *const u8,
        b: *const u8,
        m: *const u8,
        len: usize,
    ) -> bool;

    pub fn ecall_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> bool;

    pub fn ecall_convert(
        format: FormatConversion,
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_max_len: usize,
    ) -> usize;
}
