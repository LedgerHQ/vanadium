use core::panic;
use std::io;
use std::io::Write;

use crate::ecalls::EcallsInterface;
use common::ecall_constants::{CurveKind, MAX_BIGNUMBER_SIZE};
use common::ux::{EventCode, EventData};

use bip32::{ChildNumber, XPrv};
use hex_literal::hex;
use k256::{
    ecdsa::{
        self,
        signature::{hazmat::PrehashVerifier, SignerMut},
    },
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    schnorr::{self, signature::Verifier},
    EncodedPoint, ProjectivePoint, Scalar,
};

use num_bigint::BigUint;
use num_traits::Zero;

const TICKER_MS: u64 = 100;

unsafe fn to_bigint(bytes: *const u8, len: usize) -> BigUint {
    let bytes = std::slice::from_raw_parts(bytes, len);
    BigUint::from_bytes_be(bytes)
}

unsafe fn copy_result(r: *mut u8, result_bytes: &[u8], len: usize) -> () {
    if result_bytes.len() < len {
        std::ptr::write_bytes(r, 0, len - result_bytes.len());
    }
    std::ptr::copy_nonoverlapping(
        result_bytes.as_ptr(),
        r.add(len - result_bytes.len()),
        result_bytes.len(),
    );
}

pub struct Ecall;

static mut LAST_EVENT: Option<(EventCode, EventData)> = None;

impl EcallsInterface for Ecall {
    fn ux_idle() {}

    fn exit(status: i32) -> ! {
        std::process::exit(status);
    }

    fn fatal(msg: *const u8, size: usize) -> ! {
        // print the message as a panic
        let slice = unsafe { std::slice::from_raw_parts(msg, size) };
        let msg = std::str::from_utf8(slice).unwrap();
        panic!("{}", msg);
    }

    fn xsend(buffer: *const u8, size: usize) {
        let slice = unsafe { std::slice::from_raw_parts(buffer, size) };
        for byte in slice {
            print!("{:02x}", byte);
        }
        print!("\n");
        io::stdout().flush().expect("Failed to flush stdout");
    }

    fn xrecv(buffer: *mut u8, max_size: usize) -> usize {
        // Request a hex string from the user; repeat until the input is valid
        // and at most max_size bytes long
        let (n_bytes_to_copy, bytes) = loop {
            let mut input = String::new();
            io::stdout().flush().expect("Failed to flush stdout");
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");

            let input = input.trim();

            let Ok(bytes) = hex::decode(input) else {
                println!(
                    "Input too large, max size is {} bytes, please try again.",
                    max_size
                );
                continue;
            };
            if bytes.len() <= max_size {
                break (bytes.len(), bytes);
            }
            println!("Input too large, please try again.");
        };

        // copy to the destination buffer
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, n_bytes_to_copy);
        }

        return n_bytes_to_copy;
    }

    fn get_event(data: *mut EventData) -> u32 {
        if data.is_null() {
            panic!("The EventData pointer must not be null");
        }

        unsafe {
            if let Some((event_code, event_data)) = LAST_EVENT.take() {
                std::ptr::write(data, event_data);
                return event_code as u32;
            }
        }

        // for now there is no other type of event than the ticker.
        // We wait for TICKER_MS milliseconds and return a Ticker event.
        std::thread::sleep(std::time::Duration::from_millis(TICKER_MS));
        return EventCode::Ticker as u32;
    }

    fn show_page(page_desc: *const u8, page_desc_len: usize) -> u32 {
        // make a slice from page_desc and page_desc_len
        let page_desc_slice = unsafe { std::slice::from_raw_parts(page_desc, page_desc_len) };

        let Ok(page_desc) = common::ux::Page::deserialize(page_desc_slice) else {
            return 0;
        };

        match page_desc {
            common::ux::Page::Spinner { text } => {
                println!("{}...", text);
            }
            common::ux::Page::Info { icon, text } => match icon {
                common::ux::Icon::None => println!("{}", text),
                common::ux::Icon::Success => println!("✓ {}", text),
                common::ux::Icon::Failure => println!("❌ {}", text),
            },
            common::ux::Page::ConfirmReject {
                title,
                text,
                confirm,
                reject,
            } => {
                println!("{}\n{}", title, text);
                println!("Actions:\n - {}: C\n - {}: R", confirm, reject);
                loop {
                    let mut input = String::new();
                    io::stdin()
                        .read_line(&mut input)
                        .expect("Failed to read line");

                    match input.trim() {
                        // TODO: wrong! Should create an event instead
                        "C" => return 1,
                        "R" => return 0,
                        _ => continue,
                    }
                }
                // wait for either Esc or Enter to be pressed
            }
        }

        1
    }

    fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE || len_m > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        if len_m > len_m {
            return 0;
        }

        let n = unsafe { to_bigint(n, len) };
        let m = unsafe { to_bigint(m, len_m) };

        if m.is_zero() {
            return 0;
        }

        let result = n % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = (a + b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        // the `+ &m` is to avoid negative numbers, since BigUints must be non-negative
        let result = ((a + &m) - b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
        if len > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let b = unsafe { to_bigint(b, len) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m || b >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = (a * b) % &m;
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn bn_powm(
        r: *mut u8,
        a: *const u8,
        e: *const u8,
        len_e: usize,
        m: *const u8,
        len: usize,
    ) -> u32 {
        if len > MAX_BIGNUMBER_SIZE || len_e > MAX_BIGNUMBER_SIZE {
            return 0;
        }

        let a = unsafe { to_bigint(a, len) };
        let e = unsafe { to_bigint(e, len_e) };
        let m = unsafe { to_bigint(m, len) };

        if a >= m {
            return 0;
        }

        if m.is_zero() {
            return 0;
        }

        let result = a.modpow(&e, &m);
        let result_bytes = result.to_bytes_be();

        if result_bytes.len() > len {
            return 0;
        }

        unsafe {
            copy_result(r, &result_bytes, len);
        }

        1
    }

    fn derive_hd_node(
        curve: u32,
        path: *const u32,
        path_len: usize,
        privkey: *mut u8,
        chain_code: *mut u8,
    ) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }
        let mut key = Ecall::get_master_bip32_key();

        let path_slice = unsafe { std::slice::from_raw_parts(path, path_len) };
        for path_step in path_slice {
            let child = ChildNumber::from(*path_step);
            key = match key.derive_child(child) {
                Ok(k) => k,
                Err(_) => return 0,
            };
        }

        // Copy the private key and chain code to the output buffers
        let privkey_bytes = key.private_key().to_bytes();
        let chain_code_bytes = key.attrs().chain_code;

        unsafe {
            std::ptr::copy_nonoverlapping(privkey_bytes.as_ptr(), privkey, privkey_bytes.len());
            std::ptr::copy_nonoverlapping(
                chain_code_bytes.as_ptr(),
                chain_code,
                chain_code_bytes.len(),
            );
        }

        1
    }

    fn get_master_fingerprint(curve: u32) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        u32::from_be_bytes(Ecall::get_master_bip32_key().public_key().fingerprint())
    }

    fn ecfp_add_point(curve: u32, r: *mut u8, p: *const u8, q: *const u8) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        let p_slice = unsafe { std::slice::from_raw_parts(p, 65) };
        let q_slice = unsafe { std::slice::from_raw_parts(q, 65) };

        let p_point = EncodedPoint::from_bytes(p_slice).expect("Invalid point P");
        let q_point = EncodedPoint::from_bytes(q_slice).expect("Invalid point Q");

        let p_point = ProjectivePoint::from_encoded_point(&p_point).unwrap();
        let q_point = ProjectivePoint::from_encoded_point(&q_point).unwrap();

        let result_point = p_point + q_point;

        let result_encoded = result_point.to_encoded_point(false);
        let result_bytes = result_encoded.as_bytes();

        unsafe {
            std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), r, result_bytes.len());
        }

        1
    }

    fn ecfp_scalar_mult(curve: u32, r: *mut u8, p: *const u8, k: *const u8, k_len: usize) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }
        if k_len > 32 {
            panic!("k_len is too large");
        }

        let p_slice = unsafe { std::slice::from_raw_parts(p, 65) };
        let k_slice = unsafe { std::slice::from_raw_parts(k, k_len) };

        let p_point = EncodedPoint::from_bytes(p_slice).expect("Invalid point P");
        let p_point = ProjectivePoint::from_encoded_point(&p_point).unwrap();

        // pad k_scalar to 32 bytes with initial zeros without using unsafe code
        let mut k_scalar = [0u8; 32];
        k_scalar[32 - k_len..].copy_from_slice(k_slice);
        let k_scalar = Scalar::from_repr(k_scalar.into()).unwrap();

        let result_point = p_point * k_scalar;
        let result_encoded = result_point.to_encoded_point(false);

        let result_bytes = result_encoded.as_bytes();

        unsafe {
            std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), r, result_bytes.len());
        }

        1
    }

    fn ecdsa_sign(
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: *const u8,
        msg_hash: *const u8,
        signature: *mut u8,
    ) -> usize {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        if mode != common::ecall_constants::EcdsaSignMode::RFC6979 as u32 {
            panic!("Invalid or unsupported ecdsa signing mode");
        }

        if hash_id != common::ecall_constants::HashId::Sha256 as u32 {
            panic!("Invalid or unsupported hash id");
        }

        let privkey_slice = unsafe { std::slice::from_raw_parts(privkey, 32) };
        let msg_hash_slice = unsafe { std::slice::from_raw_parts(msg_hash, 32) };

        let mut privkey_bytes = [0u8; 32];
        privkey_bytes[..].copy_from_slice(privkey_slice);
        let signing_key =
            ecdsa::SigningKey::from_bytes(&privkey_bytes.into()).expect("Invalid private key");
        let (signature_local, _) = signing_key
            .sign_prehash_recoverable(msg_hash_slice)
            .expect("Signing failed");

        let signature_der = ecdsa::DerSignature::from(signature_local);

        let signature_bytes = signature_der.to_bytes();

        unsafe {
            std::ptr::copy_nonoverlapping(
                signature_bytes.as_ptr(),
                signature,
                signature_bytes.len(),
            );
        }

        signature_bytes.len()
    }

    fn ecdsa_verify(
        curve: u32,
        pubkey: *const u8,
        msg_hash: *const u8,
        signature: *const u8,
        signature_len: usize,
    ) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        if signature_len > 72 {
            panic!("signature_len is too large");
        }

        let pubkey_slice = unsafe { std::slice::from_raw_parts(pubkey, 65) };
        let msg_hash_slice = unsafe { std::slice::from_raw_parts(msg_hash, 32) };
        let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };

        let pubkey_point = EncodedPoint::from_bytes(pubkey_slice).expect("Invalid public key");
        let verifying_key = ecdsa::VerifyingKey::from_encoded_point(&pubkey_point)
            .expect("Failed to create verifying key");

        let signature =
            ecdsa::DerSignature::from_bytes(signature_slice.into()).expect("Invalid signature");

        match verifying_key.verify_prehash(msg_hash_slice, &signature) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }

    fn schnorr_sign(
        curve: u32,
        mode: u32,
        hash_id: u32,
        privkey: *const u8,
        msg: *const u8,
        msg_len: usize,
        signature: *mut u8,
    ) -> usize {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        if mode != common::ecall_constants::SchnorrSignMode::BIP340 as u32 {
            panic!("Invalid or unsupported schnorr signing mode");
        }

        if msg_len > 128 {
            panic!("msg_len is too large");
        }

        if hash_id != common::ecall_constants::HashId::Sha256 as u32 {
            panic!("Invalid or unsupported hash id");
        }

        let privkey_slice = unsafe { std::slice::from_raw_parts(privkey, 32) };
        let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };

        let mut privkey_bytes = [0u8; 32];
        privkey_bytes[..].copy_from_slice(privkey_slice);
        let mut signing_key =
            schnorr::SigningKey::from_bytes(&privkey_bytes).expect("Invalid private key");

        let signature_bytes = signing_key.sign(msg_slice).to_bytes();

        unsafe {
            std::ptr::copy_nonoverlapping(
                signature_bytes.as_ptr(),
                signature,
                signature_bytes.len(),
            );
        }

        signature_bytes.len()
    }

    fn schnorr_verify(
        curve: u32,
        mode: u32,
        hash_id: u32,
        pubkey: *const u8,
        msg: *const u8,
        msg_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> u32 {
        if curve != CurveKind::Secp256k1 as u32 {
            panic!("Unsupported curve");
        }

        if mode != common::ecall_constants::SchnorrSignMode::BIP340 as u32 {
            panic!("Invalid or unsupported schnorr signing mode");
        }

        if msg_len > 128 {
            panic!("msg_len is too large");
        }

        if hash_id != common::ecall_constants::HashId::Sha256 as u32 {
            panic!("Invalid or unsupported hash id");
        }

        if signature_len != 64 {
            panic!("Invalid signature length");
        }

        let pubkey_slice = unsafe { std::slice::from_raw_parts(pubkey, 65) };
        let xonly_pubkey_slice = &pubkey_slice[1..33];
        let msg_slice = unsafe { std::slice::from_raw_parts(msg, msg_len) };
        let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };

        let verifying_key =
            schnorr::VerifyingKey::from_bytes(xonly_pubkey_slice).expect("Invalid public key");
        let signature = schnorr::Signature::try_from(signature_slice).expect("Invalid signature");

        match verifying_key.verify(msg_slice, &signature) {
            Ok(_) => 1,
            Err(_) => 0,
        }
    }
}

impl Ecall {
    // default seed used in Speculos, corrseponding to the mnemonic "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
    const DEFAULT_SEED: [u8; 64] = hex!("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564");

    fn get_master_bip32_key() -> XPrv {
        XPrv::new(&Self::DEFAULT_SEED).expect("Failed to create master key from seed")
    }
}
