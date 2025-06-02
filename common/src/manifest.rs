use alloc::string::{String, ToString};
use serde::{self, Deserialize, Serialize};

use crate::accumulator::Hasher;
use crate::constants::{page_start, PAGE_SIZE};

const APP_NAME_MAX_LEN: usize = 32;
const APP_VERSION_MAX_LEN: usize = 32;

// TODO: copied from vanadium-legacy without much thought; fields are subject to change
/// The manifest contains all the required info that the application needs in order to execute a V-App.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub manifest_version: u32,
    pub app_name: String,
    pub app_version: String,
    pub entrypoint: u32,
    pub code_start: u32,
    pub code_end: u32,
    pub code_merkle_root: [u8; 32],
    pub data_start: u32,
    pub data_end: u32,
    pub data_merkle_root: [u8; 32],
    pub stack_start: u32,
    pub stack_end: u32,
    pub stack_merkle_root: [u8; 32],
}

impl Manifest {
    // Helper function to create a Manifest with the app_name and app_version set from &str
    pub fn new(
        manifest_version: u32,
        app_name: &str,
        app_version: &str,
        entrypoint: u32,
        code_start: u32,
        code_end: u32,
        code_merkle_root: [u8; 32],
        data_start: u32,
        data_end: u32,
        data_merkle_root: [u8; 32],
        stack_start: u32,
        stack_end: u32,
        stack_merkle_root: [u8; 32],
    ) -> Result<Self, &'static str> {
        if app_name.len() > APP_NAME_MAX_LEN {
            return Err("app_name is too long");
        }
        if app_version.len() > APP_VERSION_MAX_LEN {
            return Err("app_version is too long");
        }
        if entrypoint < code_start || entrypoint >= code_end {
            return Err("entrypoint must be within the code section");
        }
        if entrypoint % 2 != 0 {
            return Err("entrypoint must be 2-byte aligned");
        }
        if !app_name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Err("app_name contains non-printable ASCII characters");
        }
        if !app_version
            .chars()
            .all(|c| c.is_ascii_graphic() || c == ' ')
        {
            return Err("app_version contains non-printable ASCII characters");
        }
        if app_name.starts_with(' ') || app_name.ends_with(' ') {
            return Err("app_name must not start or end with a space");
        }
        if app_version.starts_with(' ') || app_version.ends_with(' ') {
            return Err("app_version must not start or end with a space");
        }

        Ok(Self {
            manifest_version,
            app_name: app_name.to_string(),
            app_version: app_version.to_string(),
            entrypoint,
            code_start,
            code_end,
            code_merkle_root,
            data_start,
            data_end,
            data_merkle_root,
            stack_start,
            stack_end,
            stack_merkle_root,
        })
    }

    pub fn get_app_name(&self) -> &str {
        &self.app_name
    }

    pub fn get_app_version(&self) -> &str {
        &self.app_version
    }

    #[inline]
    fn n_pages(start: u32, end: u32) -> u32 {
        1 + (page_start(end - 1) - page_start(start)) / PAGE_SIZE as u32
    }

    #[inline]
    pub fn n_code_pages(&self) -> u32 {
        Self::n_pages(self.code_start, self.code_end)
    }

    #[inline]
    pub fn n_data_pages(&self) -> u32 {
        Self::n_pages(self.data_start, self.data_end)
    }

    #[inline]
    pub fn n_stack_pages(&self) -> u32 {
        Self::n_pages(self.stack_start, self.stack_end)
    }

    #[cfg(feature = "serde_json")]
    pub fn to_json(&self) -> Result<alloc::string::String, serde_json::Error> {
        serde_json::to_string(self)
    }

    #[cfg(feature = "serde_json")]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Computes a hash of all the fields in the manifest.
    ///
    /// All the fields in any way for the execution of the V-App must be included in the hash.
    /// This makes sure that the hash can be used to uniquely identify the exact V-App version.
    ///
    /// This function is generic over a hasher that implements the `Hasher` trait in order to allow compiling on any
    /// target, but should only be used with a hasher for SHA-256 in order to produce the expected hashes.
    pub fn get_vapp_hash<H: Hasher<OUTPUT_SIZE>, const OUTPUT_SIZE: usize>(
        &self,
    ) -> [u8; OUTPUT_SIZE] {
        let mut hasher = H::new();

        // Hash manifest_version
        hasher.update(&self.manifest_version.to_be_bytes());

        // Hash app_name (length prefixed, as it's variable length)
        let name_len = self.app_name.len() as u8;
        hasher.update(&[name_len]);
        hasher.update(self.app_name.as_bytes());

        // Hash app_version (length prefixed, as it's variable length)
        let version_len = self.app_version.len() as u8;
        hasher.update(&[version_len]);
        hasher.update(self.app_version.as_bytes());

        // Hash entrypoint
        hasher.update(&self.entrypoint.to_be_bytes());

        // Hash code section information
        hasher.update(&self.code_start.to_be_bytes());
        hasher.update(&self.code_end.to_be_bytes());
        hasher.update(&self.code_merkle_root);

        // Hash data section information
        hasher.update(&self.data_start.to_be_bytes());
        hasher.update(&self.data_end.to_be_bytes());
        hasher.update(&self.data_merkle_root);

        // Hash stack section information
        hasher.update(&self.stack_start.to_be_bytes());
        hasher.update(&self.stack_end.to_be_bytes());
        hasher.update(&self.stack_merkle_root);

        hasher.finalize()
    }
}
