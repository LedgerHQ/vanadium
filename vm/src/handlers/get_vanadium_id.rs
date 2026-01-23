use crate::handlers::lib::vapp::get_vanadium_id;
use crate::{AppSW, COMM_BUFFER_SIZE};
use alloc::vec::Vec;

pub fn handler_get_vanadium_id(
    _command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let vanadium_id = get_vanadium_id();
    Ok(vanadium_id.to_vec())
}
