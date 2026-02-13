use crate::{AppSW, COMM_BUFFER_SIZE};
use alloc::vec::Vec;

pub fn handler_get_app_info(
    _command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let app_name = "Vanadium".as_bytes();
    let version = env!("CARGO_PKG_VERSION").as_bytes();
    let device_model = get_device_model().as_bytes();

    // Format: length-prefixed strings for app name, version, and device model
    // Each field: 1 byte length + data
    let mut response = Vec::new();

    // App name
    response.push(app_name.len() as u8);
    response.extend_from_slice(app_name);

    // Version
    response.push(version.len() as u8);
    response.extend_from_slice(version);

    // Device model
    response.push(device_model.len() as u8);
    response.extend_from_slice(device_model);

    // Vanadium app ID
    response.push(32u8);
    response.extend_from_slice(&crate::auth::get_vanadium_app_id());

    Ok(response)
}

fn get_device_model() -> &'static str {
    #[cfg(target_os = "nanox")]
    {
        "Nano X"
    }
    #[cfg(target_os = "nanosplus")]
    {
        "Nano S Plus"
    }
    #[cfg(target_os = "flex")]
    {
        "Flex"
    }
    #[cfg(target_os = "stax")]
    {
        "Stax"
    }
    #[cfg(target_os = "apex_p")]
    {
        "Nano Gen5"
    }

    #[cfg(not(any(
        target_os = "nanox",
        target_os = "nanosplus",
        target_os = "flex",
        target_os = "stax",
        target_os = "apex_p"
    )))]
    {
        compile_error!("Unsupported target OS");
        unreachable!()
    }
}
