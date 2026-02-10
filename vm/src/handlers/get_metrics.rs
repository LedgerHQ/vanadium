use alloc::vec::Vec;

use crate::{AppSW, COMM_BUFFER_SIZE};
use common::metrics::VAppMetrics;

/// Global storage for the last V-App's metrics
static mut LAST_VAPP_METRICS: VAppMetrics = VAppMetrics::new();

/// Sets the metrics for the last executed V-App.
/// # Safety
/// This function is not thread-safe, but is safe in the single-threaded Ledger environment.
pub fn set_last_metrics(metrics: VAppMetrics) {
    unsafe {
        LAST_VAPP_METRICS = metrics;
    }
}

/// Gets the metrics for the last executed V-App.
fn get_last_metrics() -> VAppMetrics {
    unsafe { LAST_VAPP_METRICS }
}

/// Handler for the GetMetrics command.
/// Returns the metrics for the last V-App that exited.
///
/// Response format:
/// - 32 bytes: V-App name (null-padded)
/// - 32 bytes: V-App hash
/// - 8 bytes: instruction count (big-endian)
/// - 4 bytes: page loads (big-endian)
/// - 4 bytes: page commits (big-endian)
///
/// Total: 80 bytes
pub fn handler_get_metrics(
    _command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let metrics = get_last_metrics();

    if !metrics.is_valid() {
        // No V-App has run yet, return error
        return Err(AppSW::IncorrectData);
    }

    let mut response = Vec::with_capacity(80);

    // V-App name (32 bytes)
    response.extend_from_slice(&metrics.vapp_name);

    // V-App hash (32 bytes)
    response.extend_from_slice(&metrics.vapp_hash);

    // Instruction count (8 bytes, big-endian)
    response.extend_from_slice(&metrics.instruction_count.to_be_bytes());

    // Page loads (4 bytes, big-endian)
    response.extend_from_slice(&metrics.page_loads.to_be_bytes());

    // Page commits (4 bytes, big-endian)
    response.extend_from_slice(&metrics.page_commits.to_be_bytes());

    Ok(response)
}
