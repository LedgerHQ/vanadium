#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

mod constants;
mod handlers;
mod resident_key;

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
        Request::GetVersion => todo!(),
        Request::Exit => sdk::exit(0),
        Request::GetMasterFingerprint => handle_get_master_fingerprint(app),
        Request::GetExtendedPubkey { path, display } => {
            handle_get_extended_pubkey(app, path, *display).await
        }
        Request::GetResidentPubkey { index, display } => {
            handle_get_resident_pubkey(app, *index, *display).await
        }
        Request::RegisterAccount { name, account } => {
            handle_register_account(app, name, account).await
        }
        Request::GetAddress {
            name,
            account,
            por,
            coordinates,
            display,
        } => handle_get_address(app, name.as_deref(), account, por, coordinates, *display).await,
        Request::SignPsbt { psbt } => handle_sign_psbt(app, psbt).await,
    }
}

#[sdk::handler]
async fn process_message(app: &mut App, request: &[u8]) -> Vec<u8> {
    let Ok(request) = postcard::from_bytes(request) else {
        return postcard::to_allocvec(&Response::Error(common::errors::Error::InvalidRequest))
            .unwrap();
    };
    let response = handle_request(app, &request)
        .await
        .unwrap_or_else(|e| Response::Error(e));
    postcard::to_allocvec(&response).unwrap()
}

pub fn main() {
    AppBuilder::new("Bitcoin", env!("CARGO_PKG_VERSION"), process_message)
        .description("Bitcoin is ready")
        .developer("Salvatore Ingala")
        .run();
}
