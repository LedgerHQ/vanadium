use lazy_static::lazy_static;
use rand::TryRngCore;
use std::{
    io::{self, Write},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    thread::sleep,
    time::Duration,
};

#[cfg(not(feature = "test-mode"))]
use std::io::Read;

use hmac::{Hmac, Mac};
use sha2::Sha512;

use sha2::Digest;

use common::{
    constants::STORAGE_SLOT_SIZE,
    ecall_constants::{
        CurveKind, HashId, CTX_RIPEMD160_SIZE, CTX_SHA256_SIZE, CTX_SHA384_SIZE, CTX_SHA3_SIZE,
        CTX_SHA512_SIZE,
    },
    ecall_validation::{
        classify_secp256k1_point, is_bignum_len, is_modulus, is_reduced,
        is_schnorr_signature_in_range, is_secp256k1_private_key, is_secp256k1_scalar, is_zero,
        parse_der_ecdsa_signature, parse_hash_identifier, parse_slip21_labels,
        reduce_secp256k1_scalar, PointEncoding, MAX_BIP32_PATH_LEN, MAX_ECDSA_SIGNATURE_LEN,
        MAX_RANDOM_BYTES, MAX_SCHNORR_MSG_LEN, MAX_SLIP21_LABELS_LEN,
    },
    ux::{Deserializable, EventCode, EventData},
    BufferType,
};

use bip32::{ChildNumber, XPrv};
use hex_literal::hex;
use k256::{
    ecdsa::{self, signature::hazmat::PrehashVerifier},
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Group, PrimeField,
    },
    schnorr, EncodedPoint, ProjectivePoint, Scalar,
};

use num_bigint::BigUint;

// default seed used in Speculos, corresponding to the mnemonic "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
const DEFAULT_SEED: [u8; 64] = hex!("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564");

const SLIP21_MAGIC: &'static str = "Symmetric key seed";

const TICKER_MS: u64 = 100;

unsafe fn copy_result(r: *mut u8, result_bytes: &[u8], len: usize) -> () {
    unsafe {
        if result_bytes.len() < len {
            std::ptr::write_bytes(r, 0, len - result_bytes.len());
        }
        std::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            r.add(len - result_bytes.len()),
            result_bytes.len(),
        );
    }
}

// This should be called in show_page if there is no action for the user after showing the page.
fn epilogue_noaction() {
    // no action, just print the closing line
    println!("\n+=========================================+");
}

fn prompt_for_action(actions: &[(char, String)]) -> char {
    assert!(
        !actions.is_empty(),
        "This method requires at least one action"
    );

    let mut seen = std::collections::HashSet::new();
    for (ch, _) in actions {
        if !seen.insert(ch) {
            panic!("Duplicate action: {}", ch);
        }
    }

    println!("-------------------------------------------\n");
    println!("Actions:");
    for (c, desc) in actions {
        println!(" - {} : {}", desc, c);
    }
    // this assumes that prompt_for_action is called in show_page as the last thing after
    // showing the page; therefore, we print the closing line here.
    println!("\n+=========================================+");

    loop {
        let mut input = String::new();
        print!("$ ");
        io::stdout().flush().expect("Failed to flush stdout");
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");
        let trimmed = input.trim();
        if trimmed.len() == 1 {
            let ch = trimmed.chars().next().unwrap();
            if actions.iter().any(|(c, _)| *c == ch) {
                return ch;
            }
        }
        // show error and print the list of valid actions (only the character)
        print!("Invalid action. Valid actions are: ");
        for (i, (c, _)) in actions.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", c);
        }
        println!();
    }
}

/// Wait for the client to connect
fn wait_for_client() -> TcpStream {
    let addr = std::env::var("VAPP_ADDRESS").unwrap_or_else(|_| "127.0.0.1:2323".into());

    loop {
        match TcpListener::bind(&addr) {
            Ok(listener) => {
                eprintln!("V-App listening on {addr}, waiting for client...");

                // block until client connects
                match listener.accept() {
                    Ok((stream, remote)) => {
                        eprintln!("Client {remote} connected");
                        let _ = stream.set_nodelay(true);
                        return stream;
                    }
                    Err(err) => {
                        eprintln!("Accept failed ({err}). Retrying...");
                        sleep(Duration::from_millis(250));
                    }
                }
            }
            Err(err) => {
                eprintln!("Can’t bind {addr} ({err}). Retrying...");
                sleep(Duration::from_millis(250));
            }
        }
    }
}

lazy_static! {
    static ref LAST_EVENT: Mutex<Option<(common::ux::EventCode, common::ux::EventData)>> =
        Mutex::new(None);
    static ref TCP_CONN: Mutex<TcpStream> = Mutex::new(wait_for_client());
}

fn get_last_event() -> Option<(common::ux::EventCode, common::ux::EventData)> {
    let mut last_event = LAST_EVENT.lock().expect("Mutex poisoned");
    last_event.take()
}

fn store_new_event(event_code: common::ux::EventCode, event_data: common::ux::EventData) {
    let mut last_event = LAST_EVENT.lock().expect("Mutex poisoned");
    // Store the new event if there is no stored event,
    // or if the currently stored event is a ticker.
    if last_event.is_none()
        || last_event
            .as_ref()
            .map_or(false, |e| e.0 == common::ux::EventCode::Ticker)
    {
        *last_event = Some((event_code, event_data));
    }
}

pub fn exit(status: i32) -> ! {
    std::process::exit(status);
}

pub fn fatal(msg: *const u8, size: usize) -> ! {
    // SAFETY: caller guarantees [buffer, buffer+size) is valid.
    let data = unsafe { std::slice::from_raw_parts(msg, size) };

    // We need to communicate the panic to the client before exiting.
    // 1 byte message type, 4-byte big-endian length, then raw payload.
    let mut stream = TCP_CONN.lock().expect("TCP mutex poisoned");
    stream
        .write_all(&[BufferType::Panic as u8])
        .and_then(|_| stream.write_all(&(size as u32).to_be_bytes()))
        .and_then(|_| stream.write_all(data))
        .and_then(|_| stream.flush())
        .expect("TCP write failed");

    // No reason not to panic also here, since we have to exit anyway
    panic!("{}", std::str::from_utf8(data).unwrap());
}

#[cfg(feature = "test-mode")]
pub fn xsend(_buffer: *const u8, _size: usize) {
    panic!("Cannot send or receive bytes in native unit tests");
}

#[cfg(not(feature = "test-mode"))]
pub fn xsend(buffer: *const u8, size: usize) {
    // SAFETY: caller guarantees [buffer, buffer+size) is valid.
    let data = unsafe { std::slice::from_raw_parts(buffer, size) };

    // 1 byte message type, 4-byte big-endian length, then raw payload.
    let mut stream = TCP_CONN.lock().expect("TCP mutex poisoned");
    stream
        .write_all(&[BufferType::VAppMessage as u8])
        .and_then(|_| stream.write_all(&(size as u32).to_be_bytes()))
        .and_then(|_| stream.write_all(data))
        .and_then(|_| stream.flush())
        .expect("TCP write failed");
}

#[cfg(feature = "test-mode")]
pub fn xrecv(_buffer: *mut u8, _max_size: usize) -> usize {
    panic!("Cannot send or receive bytes in native unit tests");
}

#[cfg(not(feature = "test-mode"))]
pub fn xrecv(buffer: *mut u8, max_size: usize) -> usize {
    let mut stream = TCP_CONN.lock().expect("TCP mutex poisoned");

    // Read the 4-byte length header first.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("TCP read failed");
    let expected = u32::from_be_bytes(len_buf) as usize;

    if expected > max_size {
        panic!(
            "Peer wants to send {} bytes but caller only provided {}-byte buffer",
            expected, max_size
        );
    }

    // Read the payload.
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, expected) };
    stream.read_exact(slice).expect("TCP read failed");
    expected
}

#[cfg(not(feature = "test-mode"))]
pub fn print(buffer: *const u8, size: usize) {
    // SAFETY: caller guarantees [buffer, buffer+size) is valid.
    let data = unsafe { std::slice::from_raw_parts(buffer, size) };

    // 1 byte message type, 4-byte big-endian length, then raw payload.
    let mut stream = TCP_CONN.lock().expect("TCP mutex poisoned");
    stream
        .write_all(&[BufferType::Print as u8])
        .and_then(|_| stream.write_all(&(size as u32).to_be_bytes()))
        .and_then(|_| stream.write_all(data))
        .and_then(|_| stream.flush())
        .expect("TCP write failed");
}

// When running unit tests, we should not perform network I/O on prints,
// since tests will run without a client.
#[cfg(feature = "test-mode")]
pub fn print(buffer: *const u8, size: usize) {
    // SAFETY: caller guarantees [buffer, buffer+size) is valid.
    let data = unsafe { std::slice::from_raw_parts(buffer, size) };
    // In tests, avoid network I/O; just emit the message to stderr for visibility.
    println!("{}", String::from_utf8_lossy(data));
}

pub fn get_event(data: *mut EventData) -> u32 {
    if data.is_null() {
        panic!("The EventData pointer must not be null");
    }

    unsafe {
        if let Some((event_code, event_data)) = get_last_event() {
            std::ptr::write(data, event_data);
            return event_code as u32;
        }
    }

    // for now there is no other type of event than the ticker.
    // We wait for TICKER_MS milliseconds and return a Ticker event.
    std::thread::sleep(std::time::Duration::from_millis(TICKER_MS));
    return EventCode::Ticker as u32;
}

pub fn show_page(page_desc: *const u8, page_desc_len: usize) -> u32 {
    // make a slice from page_desc and page_desc_len
    let page_desc_slice = unsafe { std::slice::from_raw_parts(page_desc, page_desc_len) };

    let Ok(page_desc) = common::ux::Page::deserialize_full(page_desc_slice) else {
        return 0;
    };

    println!("\n+=========================================+");
    match page_desc {
        common::ux::Page::Spinner { text } => {
            println!("{}...", text);
            epilogue_noaction();
        }
        common::ux::Page::Info { icon, text } => {
            match icon {
                common::ux::Icon::None => println!("{}", text),
                common::ux::Icon::Success => println!("✓ {}", text),
                common::ux::Icon::Failure => println!("❌ {}", text),
                // The following should not happen on the native target, since they are used for
                // small devices that implement the step UX model.
                common::ux::Icon::Confirm => println!("{}", text),
                common::ux::Icon::Reject => println!("{}", text),
                common::ux::Icon::Processing => println!("{}", text),
            }
            epilogue_noaction();
        }
        common::ux::Page::ConfirmReject {
            title,
            text,
            confirm,
            reject,
        } => {
            println!("{}\n{}", title, text);

            let actions = vec![('C', confirm.to_string()), ('R', reject.to_string())];
            store_new_event(
                common::ux::EventCode::Action,
                common::ux::EventData {
                    action: match prompt_for_action(&actions) {
                        'C' => common::ux::Action::Confirm,
                        'R' => common::ux::Action::Reject,
                        _ => panic!("Unexpected action"),
                    },
                },
            );
        }
        common::ux::Page::GenericPage {
            navigation_info,
            page_content_info,
        } => {
            let mut actions: Vec<(char, String)> = vec![];

            if let Some(title_text) = page_content_info.title {
                actions.push(('B', "Back".into()));
                println!("{}", title_text);
            }

            match page_content_info.page_content {
                common::ux::PageContent::TextSubtext { text, subtext } => {
                    println!("{}\n{}", text, subtext);
                }
                common::ux::PageContent::TagValueList { list } => {
                    for tag_value in list {
                        println!("{}: {}", tag_value.tag, tag_value.value);
                    }
                }
                common::ux::PageContent::ConfirmationButton { text, button_text } => {
                    println!("{}", text);
                    actions.push(('C', button_text.into()));
                }
                common::ux::PageContent::ConfirmationLongPress {
                    text,
                    long_press_text,
                } => {
                    println!("{}", text);
                    actions.push(('C', long_press_text.into()));
                }
            }

            if let Some(navigation_info) = navigation_info {
                let mut can_go_back = false;
                match navigation_info.nav_info {
                    common::ux::NavInfo::NavWithButtons {
                        has_back_button,
                        has_page_indicator: _,
                        quit_text,
                    } => {
                        if !has_back_button {
                            can_go_back = false;
                        }
                        if let Some(quit_text) = quit_text {
                            actions.push(('Q', quit_text.into()));
                        }
                    }
                }

                println!(
                    "\nPage {} of {}\n",
                    navigation_info.active_page + 1,
                    navigation_info.n_pages
                );
                if can_go_back && navigation_info.active_page > 0 {
                    actions.push(('P', "Previous page".into()));
                }
                if navigation_info.active_page < navigation_info.n_pages - 1 {
                    actions.push(('N', "Next page".into()));
                }
            }

            if actions.len() > 0 {
                store_new_event(
                    common::ux::EventCode::Action,
                    common::ux::EventData {
                        action: match prompt_for_action(&actions) {
                            'P' => common::ux::Action::PreviousPage,
                            'N' => common::ux::Action::NextPage,
                            'C' => common::ux::Action::Confirm,
                            'Q' => common::ux::Action::Quit,
                            _ => panic!("Unexpected action"),
                        },
                    },
                );
            } else {
                // no actions, just print the closing line
                epilogue_noaction();
            }
        }
        common::ux::Page::Home { description } => {
            println!("{}", description);
            epilogue_noaction();
        }
    }

    1
}

pub fn show_step(_step_desc: *const u8, _step_desc_len: usize) -> u32 {
    panic!("The native target implements the page UX model, not the step UX model.");
}

pub fn get_device_property(property: u32) -> u32 {
    match property {
        common::ecall_constants::DEVICE_PROPERTY_ID => 0,
        common::ecall_constants::DEVICE_PROPERTY_SCREEN_SIZE => 0, // we are in a shell
        common::ecall_constants::DEVICE_PROPERTY_FEATURES => 0,
        _ => panic!("Unsupported device property: {}", property),
    }
}

/// The bytes of a big number operand, or an empty slice for an empty operand (whose pointer may
/// be dangling).
unsafe fn bn_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

pub fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32 {
    if !is_bignum_len(len) || len_m > len {
        return 0;
    }
    let (n, m) = unsafe { (bn_bytes(n, len), bn_bytes(m, len_m)) };
    if !is_modulus(m, false) {
        return 0;
    }

    let result = BigUint::from_bytes_be(n) % BigUint::from_bytes_be(m);
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

/// The checks shared by `bn_addm`, `bn_subm` and `bn_multm`; returns the operands as integers.
unsafe fn bn_binop_operands(
    a: *const u8,
    b: *const u8,
    m: *const u8,
    len: usize,
    require_odd: bool,
) -> Option<(BigUint, BigUint, BigUint)> {
    if !is_bignum_len(len) {
        return None;
    }
    let (a, b, m) = unsafe { (bn_bytes(a, len), bn_bytes(b, len), bn_bytes(m, len)) };
    if !is_modulus(m, require_odd) || !is_reduced(a, m) || !is_reduced(b, m) {
        return None;
    }
    Some((
        BigUint::from_bytes_be(a),
        BigUint::from_bytes_be(b),
        BigUint::from_bytes_be(m),
    ))
}

pub fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
    let Some((a, b, m)) = (unsafe { bn_binop_operands(a, b, m, len, false) }) else {
        return 0;
    };
    let result = (a + b) % &m;
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

pub fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
    let Some((a, b, m)) = (unsafe { bn_binop_operands(a, b, m, len, false) }) else {
        return 0;
    };
    // the `+ &m` is to avoid negative numbers, since BigUints must be non-negative
    let result = ((a + &m) - b) % &m;
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

pub fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
    let Some((a, b, m)) = (unsafe { bn_binop_operands(a, b, m, len, true) }) else {
        return 0;
    };
    let result = (a * b) % &m;
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

/// Computes the modular inverse of `a` modulo `p`, storing the result in `r`.
/// The modulus `p` must be an odd prime; the result is unspecified otherwise.
/// Uses Fermat's little theorem: a^{-1} = a^{p-2} mod p.
pub fn bn_modinv_prime(r: *mut u8, a: *const u8, p: *const u8, len: usize) -> u32 {
    if !is_bignum_len(len) {
        return 0;
    }
    let (a, p) = unsafe { (bn_bytes(a, len), bn_bytes(p, len)) };
    if !is_modulus(p, true) || is_zero(a) || !is_reduced(a, p) {
        return 0;
    }

    let (a, p) = (BigUint::from_bytes_be(a), BigUint::from_bytes_be(p));
    // p is odd and larger than a > 0, so p >= 3
    let result = a.modpow(&(&p - BigUint::from(2u32)), &p);
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

pub fn bn_powm(
    r: *mut u8,
    a: *const u8,
    e: *const u8,
    len_e: usize,
    m: *const u8,
    len: usize,
) -> u32 {
    if !is_bignum_len(len) || !is_bignum_len(len_e) {
        return 0;
    }
    let (a, e, m) = unsafe { (bn_bytes(a, len), bn_bytes(e, len_e), bn_bytes(m, len)) };
    if !is_modulus(m, true) || !is_reduced(a, m) {
        return 0;
    }

    let result =
        BigUint::from_bytes_be(a).modpow(&BigUint::from_bytes_be(e), &BigUint::from_bytes_be(m));
    unsafe { copy_result(r, &result.to_bytes_be(), len) };
    1
}

pub fn derive_hd_node(
    curve: u32,
    path: *const u32,
    path_len: usize,
    privkey: *mut u8,
    chain_code: *mut u8,
) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 || path_len > MAX_BIP32_PATH_LEN {
        return 0;
    }
    let mut key = get_master_bip32_key();

    let path_slice = if path_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(path, path_len) }
    };
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

pub fn get_master_fingerprint(curve: u32, fingerprint: *mut u32) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        return 0;
    }

    let value = u32::from_be_bytes(get_master_bip32_key().public_key().fingerprint());
    unsafe { std::ptr::write_unaligned(fingerprint, value) };
    1
}

pub fn derive_slip21_node(labels: *const u8, labels_len: usize, out: *mut u8) -> u32 {
    if labels_len > MAX_SLIP21_LABELS_LEN {
        return 0;
    }
    let labels: &[u8] = if labels_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(labels, labels_len) }
    };
    let Some(labels) = parse_slip21_labels(labels) else {
        return 0;
    };

    // Vanadium uses a custom seed for its SLIP-21 hierarchy, for compatibility with Bolos
    // The seed is derived from a master secret using the standard SLIP-21 derivation.
    let custom_slip21_seed = slip21_custom_get_seed();
    let mut current_node = slip21_get_master_node(&custom_slip21_seed);
    for label in labels {
        current_node = slip21_derive_child_node(&current_node, label);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(current_node.as_ptr(), out, current_node.len());
    }

    1
}

/// Decodes a 65-byte point, if it is valid: either infinity, encoded as 65 zero bytes, or
/// `0x04 || x || y` with canonical coordinates of a point on the curve.
fn decode_secp256k1_point(bytes: &[u8; 65]) -> Option<ProjectivePoint> {
    match classify_secp256k1_point(bytes)? {
        PointEncoding::Infinity => Some(ProjectivePoint::IDENTITY),
        PointEncoding::Affine => {
            let encoded = EncodedPoint::from_bytes(bytes).ok()?;
            Option::from(ProjectivePoint::from_encoded_point(&encoded))
        }
    }
}

/// Writes a point to `r`, encoding infinity as 65 zero bytes.
unsafe fn write_secp256k1_point(r: *mut u8, point: &ProjectivePoint) {
    let mut bytes = [0u8; 65];
    if !bool::from(point.is_identity()) {
        bytes.copy_from_slice(point.to_encoded_point(false).as_bytes());
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), r, 65) };
}

pub fn ecfp_add_point(curve: u32, r: *mut u8, p: *const u8, q: *const u8) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        return 0;
    }
    let (p, q) = unsafe { (&*(p as *const [u8; 65]), &*(q as *const [u8; 65])) };
    let (Some(p), Some(q)) = (decode_secp256k1_point(p), decode_secp256k1_point(q)) else {
        return 0;
    };

    unsafe { write_secp256k1_point(r, &(p + q)) };
    1
}

pub fn ecfp_scalar_mult(curve: u32, r: *mut u8, p: *const u8, k: *const u8, k_len: usize) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 || k_len > 32 {
        return 0;
    }
    let p = unsafe { &*(p as *const [u8; 65]) };
    let Some(p) = decode_secp256k1_point(p) else {
        return 0;
    };
    let mut k_bytes = [0u8; 32];
    if k_len > 0 {
        k_bytes[32 - k_len..].copy_from_slice(unsafe { std::slice::from_raw_parts(k, k_len) });
    }
    if !is_secp256k1_scalar(&k_bytes) {
        return 0;
    }
    let k = Option::<Scalar>::from(Scalar::from_repr(k_bytes.into()))
        .expect("k is smaller than the curve order");

    unsafe { write_secp256k1_point(r, &(p * k)) };
    1
}

pub fn get_random_bytes(buffer: *mut u8, size: usize) -> u32 {
    if size > MAX_RANDOM_BYTES {
        return 0;
    }
    if size == 0 {
        return 1;
    }

    let mut rng = rand::rngs::OsRng::default();
    let mut random_bytes = [0u8; MAX_RANDOM_BYTES];
    rng.try_fill_bytes(&mut random_bytes[..size])
        .expect("Failed to generate random bytes");

    unsafe {
        std::ptr::copy_nonoverlapping(random_bytes.as_ptr(), buffer, size);
    }

    1
}

pub fn ecdsa_sign(
    curve: u32,
    mode: u32,
    hash_id: u32,
    privkey: *const u8,
    msg_hash: *const u8,
    signature: *mut u8,
) -> usize {
    if curve != CurveKind::Secp256k1 as u32
        || mode != common::ecall_constants::EcdsaSignMode::RFC6979 as u32
        || hash_id != common::ecall_constants::HashId::Sha256 as u32
    {
        return 0;
    }

    let privkey = unsafe { &*(privkey as *const [u8; 32]) };
    if !is_secp256k1_private_key(privkey) {
        return 0;
    }
    // Like the VM, sign the hash reduced modulo n. This changes neither the RFC 6979 nonce nor the
    // signature, but k256 would derive the nonce from the unreduced hash.
    let msg_hash = reduce_secp256k1_scalar(unsafe { &*(msg_hash as *const [u8; 32]) });

    let signing_key =
        ecdsa::SigningKey::from_bytes(&(*privkey).into()).expect("the private key is valid");
    let (signature_local, _) = signing_key
        .sign_prehash_recoverable(&msg_hash)
        .expect("signing with a valid key cannot fail");
    let signature_bytes = ecdsa::DerSignature::from(signature_local).to_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
    }
    signature_bytes.len()
}

pub fn ecdsa_verify(
    curve: u32,
    pubkey: *const u8,
    msg_hash: *const u8,
    signature: *const u8,
    signature_len: usize,
) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 || signature_len > MAX_ECDSA_SIGNATURE_LEN {
        return 0;
    }

    let pubkey = unsafe { &*(pubkey as *const [u8; 65]) };
    let msg_hash = reduce_secp256k1_scalar(unsafe { &*(msg_hash as *const [u8; 32]) });
    let signature = if signature_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(signature, signature_len) }
    };

    let Some(point) = decode_secp256k1_point(pubkey) else {
        return 0;
    };
    let Ok(verifying_key) = ecdsa::VerifyingKey::from_affine(point.to_affine()) else {
        // the point at infinity
        return 0;
    };
    let Some((r, s)) = parse_der_ecdsa_signature(signature) else {
        return 0;
    };
    let signature = ecdsa::Signature::from_scalars(r, s).expect("r and s are in range");
    // high-S signatures are valid ECDSA signatures, which k256 rejects unless normalized
    let signature = signature.normalize_s().unwrap_or(signature);

    match verifying_key.verify_prehash(&msg_hash, &signature) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

pub fn schnorr_sign(
    curve: u32,
    mode: u32,
    hash_id: u32,
    privkey: *const u8,
    msg: *const u8,
    msg_len: usize,
    signature: *mut u8,
    entropy: *const [u8; 32],
) -> usize {
    if curve != CurveKind::Secp256k1 as u32
        || mode != common::ecall_constants::SchnorrSignMode::BIP340 as u32
        || hash_id != common::ecall_constants::HashId::Sha256 as u32
        || msg_len > MAX_SCHNORR_MSG_LEN
    {
        return 0;
    }

    let privkey = unsafe { &*(privkey as *const [u8; 32]) };
    if !is_secp256k1_private_key(privkey) {
        return 0;
    }
    let msg = if msg_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };

    // Like the VM, use fresh auxiliary randomness if none is given.
    let aux_rand = if entropy.is_null() {
        let mut aux_rand = [0u8; 32];
        rand::rngs::OsRng::default()
            .try_fill_bytes(&mut aux_rand)
            .expect("Failed to generate random bytes");
        aux_rand
    } else {
        unsafe { *entropy }
    };

    let signing_key = schnorr::SigningKey::from_bytes(privkey).expect("the private key is valid");
    let Ok(signature_local) = signing_key.sign_raw(msg, &aux_rand) else {
        // only if the nonce is 0, or larger than n, which has negligible probability
        return 0;
    };
    let signature_bytes = signature_local.to_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(signature_bytes.as_ptr(), signature, signature_bytes.len());
    }
    signature_bytes.len()
}

pub fn schnorr_verify(
    curve: u32,
    mode: u32,
    hash_id: u32,
    pubkey: *const u8,
    msg: *const u8,
    msg_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> u32 {
    if curve != CurveKind::Secp256k1 as u32
        || mode != common::ecall_constants::SchnorrSignMode::BIP340 as u32
        || hash_id != common::ecall_constants::HashId::Sha256 as u32
        || msg_len > MAX_SCHNORR_MSG_LEN
        || signature_len != 64
    {
        return 0;
    }

    let x = unsafe { std::slice::from_raw_parts(pubkey, 32) };
    let msg = if msg_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };
    let signature = unsafe { &*(signature as *const [u8; 64]) };

    if !is_schnorr_signature_in_range(signature) {
        return 0;
    }
    let Ok(verifying_key) = schnorr::VerifyingKey::from_bytes(x) else {
        return 0;
    };
    let Ok(signature) = schnorr::Signature::try_from(&signature[..]) else {
        return 0;
    };

    match verifying_key.verify_raw(msg, &signature) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

fn get_master_bip32_key() -> XPrv {
    XPrv::new(&DEFAULT_SEED).expect("Failed to create master key from seed")
}

// custom master seed used in Vanadium's version of SLIP-21 for compatibility with Bolos
const SEED_MASTER_PATH: &'static str = "VANADIUM";
fn slip21_custom_get_seed() -> [u8; 32] {
    let m = slip21_get_master_node(&DEFAULT_SEED);
    let c = slip21_derive_child_node(&m, SEED_MASTER_PATH.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&c[32..64]);
    seed
}

fn slip21_get_master_node(seed: &[u8]) -> [u8; 64] {
    // compute HMAC-SHA512(key = SLIP21_MAGIC, msg = seed)
    let mut mac = Hmac::<Sha512>::new_from_slice(SLIP21_MAGIC.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(seed);
    mac.finalize().into_bytes().into()
}

fn slip21_derive_child_node(cur_node: &[u8; 64], label: &[u8]) -> [u8; 64] {
    // compute HMAC-SHA512(key = cur_node[:32], msg = [0] + label)
    let mut mac =
        Hmac::<Sha512>::new_from_slice(&cur_node[..32]).expect("HMAC can take key of any size");
    mac.update(&[0u8]);
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn get_storage_file() -> String {
    // Allow overriding the storage file path via environment variable,
    // which is useful for test isolation (each test instance gets its own file).
    if let Ok(path) = std::env::var("VAPP_STORAGE_FILE") {
        return path;
    }

    let file_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .expect("Failed to compute name of storage file");

    format!("{}.dat", file_name)
}

pub fn storage_read(slot_index: u32, buffer: *mut u8, buffer_size: usize) -> u32 {
    if buffer_size != common::constants::STORAGE_SLOT_SIZE {
        eprintln!(
            "storage_read: buffer_size must be {}, got {}",
            common::constants::STORAGE_SLOT_SIZE,
            buffer_size
        );
        return 0;
    }

    if slot_index >= common::constants::MAX_STORAGE_SLOTS {
        eprintln!(
            "storage_read: slot_index {} exceeds maximum {}",
            slot_index,
            common::constants::MAX_STORAGE_SLOTS
        );
        return 0;
    }

    let storage_file = get_storage_file();
    let offset = (slot_index as u64) * (common::constants::STORAGE_SLOT_SIZE as u64);

    let data = match std::fs::File::open(&storage_file) {
        Ok(mut file) => {
            use std::io::{Read, Seek, SeekFrom};

            // Seek to the slot position
            if file.seek(SeekFrom::Start(offset)).is_err() {
                // If seek fails, return zeros
                [0u8; STORAGE_SLOT_SIZE]
            } else {
                let mut data = [0u8; STORAGE_SLOT_SIZE];
                // Read the slot data, or return zeros if read fails or is incomplete
                match file.read_exact(&mut data) {
                    Ok(_) => data,
                    Err(_) => [0u8; STORAGE_SLOT_SIZE],
                }
            }
        }
        Err(_) => {
            // File doesn't exist, return zeros
            [0u8; STORAGE_SLOT_SIZE]
        }
    };

    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, STORAGE_SLOT_SIZE);
    }

    1
}

pub fn storage_write(slot_index: u32, buffer: *const u8, buffer_size: usize) -> u32 {
    if buffer_size != common::constants::STORAGE_SLOT_SIZE {
        eprintln!(
            "storage_write: buffer_size must be {}, got {}",
            common::constants::STORAGE_SLOT_SIZE,
            buffer_size
        );
        return 0;
    }

    if slot_index >= common::constants::MAX_STORAGE_SLOTS {
        eprintln!(
            "storage_write: slot_index {} exceeds maximum {}",
            slot_index,
            common::constants::MAX_STORAGE_SLOTS
        );
        return 0;
    }

    let mut data = [0u8; STORAGE_SLOT_SIZE];
    unsafe {
        std::ptr::copy_nonoverlapping(buffer, data.as_mut_ptr(), STORAGE_SLOT_SIZE);
    }

    let storage_file = get_storage_file();
    let offset = (slot_index as u64) * (common::constants::STORAGE_SLOT_SIZE as u64);

    use std::io::{Seek, SeekFrom, Write};

    // Open file for reading and writing, create if doesn't exist
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&storage_file)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("storage_write: failed to open file {}: {}", storage_file, e);
            return 0;
        }
    };

    // Get file size
    let file_size = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            eprintln!("storage_write: failed to get file metadata: {}", e);
            return 0;
        }
    };

    // If file is smaller than the required offset + slot size, extend it with zeros
    let required_size = offset + (common::constants::STORAGE_SLOT_SIZE as u64);
    if file_size < required_size {
        if file.seek(SeekFrom::End(0)).is_err() {
            eprintln!("storage_write: failed to seek to end of file");
            return 0;
        }
        let padding = vec![0u8; (required_size - file_size) as usize];
        if file.write_all(&padding).is_err() {
            eprintln!("storage_write: failed to extend file with zeros");
            return 0;
        }
    }

    // Seek to the slot position
    if file.seek(SeekFrom::Start(offset)).is_err() {
        eprintln!("storage_write: failed to seek to slot offset");
        return 0;
    }

    // Write the slot data
    if file.write_all(&data).is_err() {
        eprintln!("storage_write: failed to write slot data");
        return 0;
    }

    // Ensure data is written to disk
    if file.flush().is_err() {
        eprintln!("storage_write: failed to flush file");
        return 0;
    }

    1
}

// Compile-time size checks: hashers must fit in the context structs
const _: () = assert!(
    std::mem::size_of::<sha2::Sha256>() <= CTX_SHA256_SIZE,
    "sha2::Sha256 does not fit in CtxSha256",
);
const _: () = assert!(
    std::mem::size_of::<sha2::Sha384>() <= CTX_SHA384_SIZE,
    "sha2::Sha384 does not fit in CtxSha384",
);
const _: () = assert!(
    std::mem::size_of::<sha2::Sha512>() <= CTX_SHA512_SIZE,
    "sha2::Sha512 does not fit in CtxSha512",
);
const _: () = assert!(
    std::mem::size_of::<ripemd::Ripemd160>() <= CTX_RIPEMD160_SIZE,
    "ripemd::Ripemd160 does not fit in CtxRipemd160",
);
// All sha3/keccak variants wrap the same Keccak-f[1600] state, so checking one representative
// of each family is sufficient.
const _: () = assert!(
    std::mem::size_of::<sha3::Keccak256>() <= CTX_SHA3_SIZE,
    "sha3::Keccak256 does not fit in CTX_SHA3_SIZE",
);
const _: () = assert!(
    std::mem::size_of::<sha3::Sha3_256>() <= CTX_SHA3_SIZE,
    "sha3::Sha3_256 does not fit in CTX_SHA3_SIZE",
);

fn hash_init_as<H: Digest>(ctx: *mut u8) {
    unsafe { std::ptr::write_unaligned(ctx as *mut H, H::new()) };
}

// SAFETY (for hash_update_as and hash_final_as): the callers of the hash ECALLs guarantee that
// `ctx` holds an `H` written by hash_init_as or hash_update_as. That is not merely a matter of
// getting the right digest: a hasher can rely on invariants of its state for soundness.
fn hash_update_as<H: Digest>(ctx: *mut u8, data: &[u8]) {
    let mut hasher = unsafe { std::ptr::read_unaligned(ctx as *const H) };
    hasher.update(data);
    unsafe { std::ptr::write_unaligned(ctx as *mut H, hasher) };
}

/// Finalizes a copy of the context, leaving the context itself unchanged, as the VM does.
fn hash_final_as<H: Digest>(ctx: *mut u8, digest: *mut u8) {
    let hasher = unsafe { std::ptr::read_unaligned(ctx as *const H) };
    let result = hasher.finalize();
    unsafe { std::ptr::copy_nonoverlapping(result.as_ptr(), digest, result.len()) };
}

/// Calls `$f::<H>($args)` with the hasher `H` that implements `hash_identifier`, or returns 0 if
/// the identifier is not supported.
macro_rules! with_hasher {
    ($hash_identifier:expr, $f:ident($($arg:expr),*)) => {
        match parse_hash_identifier($hash_identifier) {
            Some((HashId::Ripemd160, _)) => $f::<ripemd::Ripemd160>($($arg),*),
            Some((HashId::Sha256, _)) => $f::<sha2::Sha256>($($arg),*),
            Some((HashId::Sha384, _)) => $f::<sha2::Sha384>($($arg),*),
            Some((HashId::Sha512, _)) => $f::<sha2::Sha512>($($arg),*),
            Some((HashId::Keccak, 28)) => $f::<sha3::Keccak224>($($arg),*),
            Some((HashId::Keccak, 32)) => $f::<sha3::Keccak256>($($arg),*),
            Some((HashId::Keccak, 48)) => $f::<sha3::Keccak384>($($arg),*),
            Some((HashId::Keccak, 64)) => $f::<sha3::Keccak512>($($arg),*),
            Some((HashId::Sha3, 28)) => $f::<sha3::Sha3_224>($($arg),*),
            Some((HashId::Sha3, 32)) => $f::<sha3::Sha3_256>($($arg),*),
            Some((HashId::Sha3, 48)) => $f::<sha3::Sha3_384>($($arg),*),
            Some((HashId::Sha3, 64)) => $f::<sha3::Sha3_512>($($arg),*),
            _ => return 0,
        }
    };
}

pub fn hash_init(hash_identifier: u32, ctx: *mut u8) -> u32 {
    with_hasher!(hash_identifier, hash_init_as(ctx));
    1
}

pub fn hash_update(hash_identifier: u32, ctx: *mut u8, data: *const u8, len: usize) -> u32 {
    let data = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    with_hasher!(hash_identifier, hash_update_as(ctx, data));
    1
}

pub fn hash_final(hash_identifier: u32, ctx: *mut u8, digest: *mut u8) -> u32 {
    with_hasher!(hash_identifier, hash_final_as(ctx, digest));
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slip21() {
        // testcases from https://github.com/satoshilabs/slips/blob/master/slip-0021.md
        const TEST_SEED: [u8; 64] = hex!("c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8");
        let m = slip21_get_master_node(&TEST_SEED);
        assert_eq!(
            m[32..],
            hex!("dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756")
        );

        let c = slip21_derive_child_node(&m, b"SLIP-0021");
        assert_eq!(
            c[32..],
            hex!("1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d")
        );

        assert_eq!(
            slip21_derive_child_node(&c, b"Master encryption key")[32..],
            hex!("ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde")
        );
        assert_eq!(
            slip21_derive_child_node(&c, b"Authentication key")[32..],
            hex!("47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6")
        );
    }

    macro_rules! test_hash {
        ($test_fn:ident, $ty:ty, $vectors_file:literal) => {
            #[test]
            fn $test_fn() {
                use crate::hash::Hasher as _;

                let vectors: serde_json::Value = serde_json::from_str(include_str!($vectors_file))
                    .expect("invalid test vectors JSON");

                for vector in vectors.as_array().expect("expected JSON array") {
                    let input_hex = vector["input"].as_str().expect("missing input field");
                    let expected_hex = vector["expected"].as_str().expect("missing expected field");

                    let input_bytes: Vec<u8> = if input_hex.is_empty() {
                        vec![]
                    } else {
                        hex::decode(input_hex).expect("invalid hex in input")
                    };
                    let expected_bytes =
                        hex::decode(expected_hex).expect("invalid hex in expected");

                    // Single-pass
                    let result = <$ty>::hash(&input_bytes);
                    assert_eq!(
                        &result[..],
                        expected_bytes.as_slice(),
                        "single-pass mismatch for input \"{}\"",
                        input_hex
                    );

                    // Incremental (first byte + rest) for inputs longer than 1 byte
                    if input_bytes.len() > 1 {
                        let mut hasher = <$ty>::new();
                        hasher.update(&input_bytes[..1]);
                        hasher.update(&input_bytes[1..]);
                        let result = hasher.finalize();
                        assert_eq!(
                            &result[..],
                            expected_bytes.as_slice(),
                            "incremental mismatch for input \"{}\"",
                            input_hex
                        );
                    }

                    // Incremental: one byte at a time
                    if input_bytes.len() > 1 {
                        let mut hasher = <$ty>::new();
                        for byte in &input_bytes {
                            hasher.update(&[*byte]);
                        }
                        let result = hasher.finalize();
                        assert_eq!(
                            &result[..],
                            expected_bytes.as_slice(),
                            "incremental (byte-by-byte) mismatch for input \"{}\"",
                            input_hex
                        );
                    }
                }
            }
        };
    }

    test_hash!(
        test_hash_sha256,
        crate::hash::Sha256,
        "../test-vectors/hashes/sha256.json"
    );
    test_hash!(
        test_hash_sha384,
        crate::hash::Sha384,
        "../test-vectors/hashes/sha384.json"
    );
    test_hash!(
        test_hash_sha512,
        crate::hash::Sha512,
        "../test-vectors/hashes/sha512.json"
    );
    test_hash!(
        test_hash_ripemd160,
        crate::hash::Ripemd160,
        "../test-vectors/hashes/ripemd160.json"
    );
    test_hash!(
        test_hash_sha3_224,
        crate::hash::Sha3_224,
        "../test-vectors/hashes/sha3_224.json"
    );
    test_hash!(
        test_hash_sha3_256,
        crate::hash::Sha3_256,
        "../test-vectors/hashes/sha3_256.json"
    );
    test_hash!(
        test_hash_sha3_384,
        crate::hash::Sha3_384,
        "../test-vectors/hashes/sha3_384.json"
    );
    test_hash!(
        test_hash_sha3_512,
        crate::hash::Sha3_512,
        "../test-vectors/hashes/sha3_512.json"
    );
    test_hash!(
        test_hash_keccak224,
        crate::hash::Keccak224,
        "../test-vectors/hashes/keccak224.json"
    );
    test_hash!(
        test_hash_keccak256,
        crate::hash::Keccak256,
        "../test-vectors/hashes/keccak256.json"
    );
    test_hash!(
        test_hash_keccak384,
        crate::hash::Keccak384,
        "../test-vectors/hashes/keccak384.json"
    );
    test_hash!(
        test_hash_keccak512,
        crate::hash::Keccak512,
        "../test-vectors/hashes/keccak512.json"
    );
}
