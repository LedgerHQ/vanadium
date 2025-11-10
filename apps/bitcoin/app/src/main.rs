#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

mod constants;
mod handlers;

use handlers::*;

use alloc::vec::Vec;

use common::message::{Request, Response};
use sdk::App;

sdk::bootstrap!();

fn handle_request(app: &mut App, request: &Request) -> Result<Response, common::errors::Error> {
    match request {
        Request::GetVersion => todo!(),
        Request::Exit => sdk::exit(0),
        Request::GetMasterFingerprint => handle_get_master_fingerprint(app),
        Request::GetExtendedPubkey { path, display } => {
            handle_get_extended_pubkey(app, path, *display)
        }
        Request::RegisterAccount { name, account } => handle_register_account(app, name, account),
        Request::GetAddress {
            name,
            account,
            por,
            coordinates,
            display,
        } => handle_get_address(app, name.as_deref(), account, por, coordinates, *display),
        Request::SignPsbt { psbt } => handle_sign_psbt(app, psbt),
    }
}

fn process_message(app: &mut App, request: &[u8]) -> Vec<u8> {
    let Ok(request) = postcard::from_bytes(request) else {
        return postcard::to_allocvec(&Response::Error(common::errors::Error::InvalidRequest))
            .unwrap();
    };
    let response = handle_request(app, &request).unwrap_or_else(|e| Response::Error(e));
    postcard::to_allocvec(&response).unwrap()
}

pub fn main() {
    App::new("Bitcoin", env!("CARGO_PKG_VERSION"), process_message)
        .description("Bitcoin is ready")
        .developer("Salvatore Ingala")
        .run();
}
