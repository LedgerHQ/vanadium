/// Metrics collected during the execution of a V-App.
#[derive(Clone, Copy, Default)]
#[cfg_attr(feature = "serde_json", derive(serde::Serialize, serde::Deserialize))]
pub struct VAppMetrics {
    /// Name of the V-App (null-padded to 32 bytes)
    pub vapp_name: [u8; 32],
    /// Hash of the V-App
    pub vapp_hash: [u8; 32],
    /// Number of instructions executed
    pub instruction_count: u64,
    /// Number of page loads from the host
    pub page_loads: u32,
    /// Number of page commits to the host
    pub page_commits: u32,
}

impl VAppMetrics {
    pub const fn new() -> Self {
        Self {
            vapp_name: [0u8; 32],
            vapp_hash: [0u8; 32],
            instruction_count: 0,
            page_loads: 0,
            page_commits: 0,
        }
    }

    /// Checks if metrics have been recorded (i.e., if a V-App has run)
    pub fn is_valid(&self) -> bool {
        // Check if vapp_hash is non-zero
        self.vapp_hash.iter().any(|&b| b != 0)
    }

    /// Get the V-App name as a string (strip null padding)
    pub fn get_vapp_name(&self) -> &str {
        let len = self.vapp_name.iter().position(|&b| b == 0).unwrap_or(32);
        core::str::from_utf8(&self.vapp_name[..len]).unwrap_or("")
    }
}
