use crate::{
    auth::{compute_code_page_hmac, compute_page_hmac_mask, get_vapp_auth_key},
    handlers::lib::outsourced_mem::OutsourcedMemory,
    hash::Sha256Hasher,
    io::{interrupt, SerializeToComm},
    AppSW, COMM_BUFFER_SIZE,
};
use alloc::vec::Vec;
use common::{
    accumulator::{HashOutput, MerkleAccumulatorRootComputer},
    client_commands::{GetCodePageHashes, GetCodePageHashesResponse, Message},
    manifest::Manifest,
};
use ledger_device_sdk::{nbgl::NbglSpinner, sys};

pub fn handler_preload_vapp(
    command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let data_raw = command.get_data();

    let (manifest, rest) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if rest.len() != 0 {
        return Err(AppSW::IncorrectData); // extra data
    }

    manifest.validate().map_err(|_| AppSW::IncorrectData)?; // ensure manifest is valid

    // Implements the logic to preload the V-App's code, by receiving all the page hashes from the client, and
    // sending back the encrypted HMACs; finally, after validating the Merkle root, send the decryption key.
    // See the documentation in docs/security.md for more details.

    let mut ephemeral_sk = [0u8; 32];
    unsafe {
        sys::cx_rng_no_throw(ephemeral_sk.as_mut_ptr(), ephemeral_sk.len());
    }

    let vapp_hash = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    let app_auth_key = get_vapp_auth_key(&vapp_hash);

    let mut resp = command.into_response();
    GetCodePageHashes::new(0, &[]).serialize_to_comm(&mut resp);
    let mut command = interrupt(resp).map_err(|_| AppSW::IncorrectData)?;

    NbglSpinner::new().show("Preloading V-App...");

    let n_code_pages_rounded = OutsourcedMemory::<'_, COMM_BUFFER_SIZE>::n_pages_adjusted(
        manifest.n_code_pages() as usize,
    );

    let mut n_page_hashes_received = 0usize;

    let mut root_computer =
        MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(n_code_pages_rounded);

    let mut response_data = Vec::with_capacity(GetCodePageHashesResponse::max_hashes());

    // the host will send page hashes in batches; for each batch, we respond with encrypted HMACs
    loop {
        let data = command.get_data();
        let batch =
            GetCodePageHashesResponse::deserialize(data).map_err(|_| AppSW::IncorrectData)?;

        let n_pages_in_batch = batch.n_code_pages;
        if n_pages_in_batch == 0 {
            // the client didn't send any page hash, which should only happen once all have been sent
            break;
        }

        if n_page_hashes_received + (batch.n_code_pages as usize) > n_code_pages_rounded {
            return Err(AppSW::IncorrectData); // received too many page hashes
        }

        response_data.clear();

        for page_hash_i in batch.code_page_hashes.into_iter() {
            let i = n_page_hashes_received as u32;
            let page_sk_i = compute_page_hmac_mask(&ephemeral_sk, i);
            let hmac = compute_code_page_hmac(&app_auth_key, &vapp_hash, i, page_hash_i)
                .map_err(|_| AppSW::IncorrectData)?;
            let mut encrypted_hmac_i = [0u8; 32];
            for j in 0..32 {
                encrypted_hmac_i[j] = hmac[j] ^ page_sk_i[j];
            }

            response_data.push(encrypted_hmac_i);

            // Feed the page hash into the Merkle root computer
            root_computer.feed(&HashOutput(*page_hash_i));

            n_page_hashes_received += 1;
        }

        let mut resp = command.into_response();
        // Send encrypted HMACs, and request the next batch
        GetCodePageHashes::new(n_page_hashes_received as u32, response_data.as_slice())
            .serialize_to_comm(&mut resp);
        command = interrupt(resp).map_err(|_| AppSW::IncorrectData)?;
    }

    if n_page_hashes_received != n_code_pages_rounded {
        return Err(AppSW::IncorrectData); // received incorrect number of pages
    }

    let computed_root = root_computer.root();
    if computed_root.0 != manifest.code_merkle_root {
        return Err(AppSW::IncorrectData); // Merkle root mismatch
    }

    Ok(ephemeral_sk.to_vec())
}
