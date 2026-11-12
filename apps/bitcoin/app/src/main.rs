#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

mod bip32;
mod constants;
mod handlers;
mod identity;
mod registration;
mod resident_key;
mod sp_keys;
mod ux;

use handlers::*;

use alloc::vec::Vec;

use common::message::{Request, Response};
use sdk::{App, AppBuilder};

sdk::bootstrap!();

async fn handle_request(
    app: &mut App,
    request: &Request,
) -> Result<Response, common::errors::Error> {
    match request {
        Request::GetVersion => Ok(handle_get_version()),
        Request::Exit => sdk::exit(0),
        Request::GetMasterFingerprint { tree } => handle_get_master_fingerprint(*tree),
        Request::GetExtendedPubkey {
            tree,
            path,
            display,
            identity_index,
        } => handle_get_extended_pubkey(app, *tree, path, *display, *identity_index).await,
        Request::RegisterAccount {
            name,
            account,
            registered_identities,
            key_signatures,
            show_cleartext,
        } => {
            handle_register_account(
                app,
                name,
                account,
                registered_identities.as_deref(),
                key_signatures.as_deref(),
                *show_cleartext,
            )
            .await
        }
        Request::RegisterIdentityKey { name, pubkey } => {
            handle_register_identity_key(app, name, pubkey).await
        }
        Request::GetAddress {
            name,
            account,
            por,
            coordinates,
            display,
            identity_index,
        } => {
            handle_get_address(
                app,
                name.as_deref(),
                account,
                por,
                coordinates,
                *display,
                *identity_index,
            )
            .await
        }
        Request::SignPsbt { psbt } => handle_sign_psbt(app, psbt).await,
        Request::ExportSilentPaymentScanKey { account_index } => {
            handle_export_sp_scan_key(app, *account_index).await
        }
    }
}

/// The request that `request` encodes, which must have no trailing bytes.
fn decode_request(request: &[u8]) -> Result<Request, common::errors::Error> {
    let mut decoder = minicbor::Decoder::new(request);
    let decoded = decoder
        .decode::<Request>()
        .map_err(|_| common::errors::Error::InvalidRequest)?;
    if decoder.position() != request.len() {
        return Err(common::errors::Error::InvalidRequest);
    }
    Ok(decoded)
}

#[sdk::handler]
async fn process_message(app: &mut App, request: &[u8]) -> Vec<u8> {
    let response = match decode_request(request) {
        Ok(request) => handle_request(app, &request).await,
        Err(error) => Err(error),
    };
    let response = response.unwrap_or_else(|error| Response::Error { error });
    minicbor::to_vec(&response).unwrap()
}

pub fn main() {
    AppBuilder::new("Bitcoin", env!("CARGO_PKG_VERSION"), process_message)
        .description("Bitcoin is ready")
        .developer("Salvatore Ingala")
        .run();
}
