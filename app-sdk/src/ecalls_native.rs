use lazy_static::lazy_static;
use rand::TryRngCore;
use std::{
    collections::HashMap,
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

use common::ux::{Deserializable, EventCode, EventData};
use common::{
    client_commands::BufferType,
    ecall_constants::{CurveKind, MAX_BIGNUMBER_SIZE},
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
use num_traits::Zero;

// default seed used in Speculos, corresponding to the mnemonic "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
const DEFAULT_SEED: [u8; 64] = hex!("b11997faff420a331bb4a4ffdc8bdc8ba7c01732a99a30d83dbbebd469666c84b47d09d3f5f472b3b9384ac634beba2a440ba36ec7661144132f35e206873564");

const SLIP21_MAGIC: &'static str = "Symmetric key seed";

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
    static ref STORAGE: Mutex<HashMap<u32, [u8; 32]>> = Mutex::new(HashMap::new());
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

pub fn bn_modm(r: *mut u8, n: *const u8, len: usize, m: *const u8, len_m: usize) -> u32 {
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

pub fn bn_addm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
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

pub fn bn_subm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
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

pub fn bn_multm(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32 {
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

pub fn bn_powm(
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

pub fn derive_hd_node(
    curve: u32,
    path: *const u32,
    path_len: usize,
    privkey: *mut u8,
    chain_code: *mut u8,
) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        panic!("Unsupported curve");
    }
    let mut key = get_master_bip32_key();

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

pub fn get_master_fingerprint(curve: u32) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        panic!("Unsupported curve");
    }

    u32::from_be_bytes(get_master_bip32_key().public_key().fingerprint())
}

pub fn derive_slip21_node(labels: *const u8, labels_len: usize, out: *mut u8) -> u32 {
    if out.is_null() {
        return 0;
    }

    // Vanadium uses a custom seed for its SLIP-21 hierarchy, for compatibility with Bolos
    // The seed is derived from a master secret using the standard SLIP-21 derivation.
    let custom_slip21_seed = slip21_custom_get_seed();

    let mut current_node = slip21_get_master_node(&custom_slip21_seed);

    if labels_len > 256 {
        return 0;
    }

    let labels: &[u8] = unsafe { std::slice::from_raw_parts(labels, labels_len) };

    // parse the `labels` buffer as the concatenation of a list of labels, each prefixed by its length
    // The length of each label is between 0 and 252 bytes, and the total length of the labels buffer must be
    // at most 256 bytes.

    let mut offset = 0;
    while offset < labels_len {
        if offset >= labels_len {
            return 0; // Buffer underrun
        }

        let label_len = labels[offset] as usize;
        offset += 1;

        if label_len > 252 {
            return 0; // Label too long
        }

        if offset + label_len > labels_len {
            return 0; // Buffer overrun
        }

        let label = &labels[offset..offset + label_len];
        offset += label_len;

        current_node = slip21_derive_child_node(&current_node, label);
    }

    unsafe {
        std::ptr::copy_nonoverlapping(current_node.as_ptr(), out, current_node.len());
    }

    1
}

pub fn ecfp_add_point(curve: u32, r: *mut u8, p: *const u8, q: *const u8) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        return 0;
    }

    let p_slice = unsafe { std::slice::from_raw_parts(p, 65) };
    let q_slice = unsafe { std::slice::from_raw_parts(q, 65) };

    // Helper to validate a point and copy it to the result
    let validate_and_copy = |point_slice: &[u8], source: *const u8| -> u32 {
        let encoded = match EncodedPoint::from_bytes(point_slice) {
            Ok(enc) => enc,
            Err(_) => return 0,
        };
        if ProjectivePoint::from_encoded_point(&encoded)
            .is_none()
            .into()
        {
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(source, r, 65);
        }
        1
    };

    // Handle point at infinity: represented as prefix byte 0x00
    match (p_slice[0] == 0x00, q_slice[0] == 0x00) {
        (true, true) => {
            unsafe {
                std::ptr::write_bytes(r, 0, 65);
            }
            return 1;
        }
        (true, false) => return validate_and_copy(q_slice, q),
        (false, true) => return validate_and_copy(p_slice, p),
        (false, false) => { /* Continue with normal addition */ }
    }

    // Validate and decode point P
    let p_point = match EncodedPoint::from_bytes(p_slice) {
        Ok(enc) => enc,
        Err(_) => return 0,
    };
    let p_point: ProjectivePoint = match ProjectivePoint::from_encoded_point(&p_point).into() {
        Some(pt) => pt,
        None => return 0,
    };

    // Validate and decode point Q
    let q_point = match EncodedPoint::from_bytes(q_slice) {
        Ok(enc) => enc,
        Err(_) => return 0,
    };
    let q_point: ProjectivePoint = match ProjectivePoint::from_encoded_point(&q_point).into() {
        Some(pt) => pt,
        None => return 0,
    };

    let result_point: ProjectivePoint = p_point + q_point;

    // Check if result is the point at infinity
    // The k256 library may panic when encoding the point at infinity,
    // so we check for it first
    if bool::from(result_point.is_identity()) {
        // Encode point at infinity as all zeros (65 bytes)
        unsafe {
            std::ptr::write_bytes(r, 0, 65);
        }
        return 1;
    }

    let result_encoded = result_point.to_encoded_point(false);
    let result_bytes = result_encoded.as_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), r, result_bytes.len());
    }

    1
}

pub fn ecfp_scalar_mult(curve: u32, r: *mut u8, p: *const u8, k: *const u8, k_len: usize) -> u32 {
    if curve != CurveKind::Secp256k1 as u32 {
        return 0;
    }
    if k_len > 32 {
        return 0;
    }

    let p_slice = unsafe { std::slice::from_raw_parts(p, 65) };
    let k_slice = unsafe { std::slice::from_raw_parts(k, k_len) };

    // Validate and decode point P
    let p_point = match EncodedPoint::from_bytes(p_slice) {
        Ok(enc) => enc,
        Err(_) => return 0,
    };
    let p_point: ProjectivePoint = match ProjectivePoint::from_encoded_point(&p_point).into() {
        Some(pt) => pt,
        None => return 0,
    };

    // pad k_scalar to 32 bytes with initial zeros without using unsafe code
    let mut k_scalar = [0u8; 32];
    k_scalar[32 - k_len..].copy_from_slice(k_slice);
    let k_scalar: Scalar = match Scalar::from_repr(k_scalar.into()).into() {
        Some(scalar) => scalar,
        None => return 0,
    };

    let result_point: ProjectivePoint = p_point * k_scalar;

    // Check if result is the point at infinity
    if bool::from(result_point.is_identity()) {
        // Encode point at infinity as all zeros (65 bytes)
        unsafe {
            std::ptr::write_bytes(r, 0, 65);
        }
        return 1;
    }

    let result_encoded = result_point.to_encoded_point(false);
    let result_bytes = result_encoded.as_bytes();

    unsafe {
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), r, result_bytes.len());
    }

    1
}

pub fn get_random_bytes(buffer: *mut u8, size: usize) -> u32 {
    if size == 0 {
        return 1;
    }
    if size > 256 {
        panic!("size is too large");
    }

    let mut rng = rand::rngs::OsRng::default();
    let mut random_bytes = [0u8; 256];
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
    let signing_key = schnorr::SigningKey::from_bytes(&privkey_bytes).expect("Invalid private key");

    let aux_rand = if entropy.is_null() {
        // generate 32 random bytes
        let mut aux_rand = [0u8; 32];
        rand::rngs::OsRng::default()
            .try_fill_bytes(&mut aux_rand)
            .expect("Failed to generate random bytes");
        aux_rand
    } else {
        unsafe { *entropy }
    };

    let signature_bytes = signing_key
        .sign_raw(msg_slice, &aux_rand)
        .unwrap()
        .to_bytes();

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

    match verifying_key.verify_raw(msg_slice, &signature) {
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

pub fn storage_read(slot_index: u32, buffer: *mut u8, buffer_size: usize) -> u32 {
    if buffer_size != common::constants::STORAGE_SLOT_SIZE {
        eprintln!(
            "storage_read: buffer_size must be {}, got {}",
            common::constants::STORAGE_SLOT_SIZE,
            buffer_size
        );
        return 0;
    }

    let storage = STORAGE.lock().expect("Storage mutex poisoned");

    let data = storage.get(&slot_index).copied().unwrap_or([0u8; 32]);

    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, 32);
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

    let mut data = [0u8; 32];
    unsafe {
        std::ptr::copy_nonoverlapping(buffer, data.as_mut_ptr(), 32);
    }

    let mut storage = STORAGE.lock().expect("Storage mutex poisoned");
    storage.insert(slot_index, data);

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
}
