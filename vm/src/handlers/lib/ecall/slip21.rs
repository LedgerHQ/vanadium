// Because of Bolos' limited support for SLIP21, we use a separate key hierarchy that is compatible with
// the keys that we have available in normal Ledger apps.
//
// These are Bolos limitations for using SLIP-21 in Vanadium:
// - It is not possible to derive the master SLIP-21 node.
// - It does not return the chain code (initial 32 bytes) of any node, but only the key.
// - All the required paths must be specified in the Ledger app manifest.
//
// Therefore, we instead use a single, standard SLIP-21 key that is accessible to ledger apps, and use it
// as the root secret for the SLIP-21 key hierarchy. This allows to make sure that we can derive these keys
// from the seed in Vanadium today, without depending on the OS updates.
//
// In the notation of SLIP-21, we set:
//   S_v = m/"VANADIUM"
// where m is the master node computed using the BIP-39 seed S.
//
// Then, we compute the master node v as:
//   m_v = HMAC-SHA512(key = b"Symmetric key seed", msg = S_v)
//
// Further derivations are done as in SLIP-21.

use alloc::vec::Vec;

use ledger_device_sdk::hmac::{sha2::Sha2_512, HMACInit};
use ledger_secure_sdk_sys as sys;

const SLIP21_MAGIC: &'static str = "Symmetric key seed";

const SEED_MASTER_PATH: &'static str = "VANADIUM";

fn get_seed() -> [u8; 32] {
    // prepend a 0x00 byte to SEED_MASTER_PATH, as required by Bolos
    let mut path = Vec::with_capacity(SEED_MASTER_PATH.len() + 1);
    path.push(0x00);
    path.extend_from_slice(SEED_MASTER_PATH.as_bytes());
    // let mut seed = [0u8; 32];
    // unsafe {
    //     sys::os_perso_derive_node_with_seed_key(
    //         sys::HDW_SLIP21,
    //         sys::CX_CURVE_SECP256K1,
    //         path.as_ptr() as *const u32,
    //         path.len() as u32,
    //         seed.as_mut_ptr(),
    //         core::ptr::null_mut(),
    //         core::ptr::null_mut(),
    //         0,
    //     );
    // }

    // TODO: remove this once the Rust SDK has proper SLIP-21 path support
    // We use a dummy seed for testing purposes.
    let mut seed = [42u8; 32];

    seed
}

fn get_master_node() -> [u8; 64] {
    // compute the custom seed using standard SLIP-21
    let seed = get_seed();

    // compute HMAC-SHA512(key = SLIP21_MAGIC, msg = seed)
    let mut mac = Sha2_512::new(SLIP21_MAGIC.as_bytes());
    mac.update(&seed).expect("Should never fail");
    let mut output = [0u8; 64];
    mac.finalize(&mut output).expect("Should never fail");
    output
}

fn derive_child_node(cur_node: &[u8; 64], label: &[u8]) -> [u8; 64] {
    // compute HMAC-SHA512(key = cur_node[:32], msg = [0] + label)
    let mut mac = Sha2_512::new(&cur_node[..32]);
    mac.update(&[0u8]).expect("Should never fail");
    mac.update(label).expect("Should never fail");
    let mut output = [0u8; 64];
    mac.finalize(&mut output).expect("Should never fail");
    output
}

pub fn get_custom_slip21_node(path: &[&[u8]]) -> [u8; 64] {
    let master_node = get_master_node();

    let mut current_node = master_node;
    for label in path {
        current_node = derive_child_node(&current_node, label);
    }

    current_node
}
