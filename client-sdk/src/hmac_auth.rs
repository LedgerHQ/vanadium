use std::path::{Path, PathBuf};

use common::manifest::Manifest;

/// Magic bytes for the HMAC cache file format.
const HMAC_FILE_MAGIC: &[u8; 10] = b"VAPP_HMAC\0";

/// Computes the V-App hash from a manifest.
pub fn compute_vapp_hash(manifest: &Manifest) -> [u8; 32] {
    use crate::hash::Sha256;
    manifest.get_vapp_hash::<Sha256, 32>()
}

/// Returns the `.hmac` file path corresponding to an ELF path.
pub fn hmac_file_path(elf_path: &str) -> PathBuf {
    let p = Path::new(elf_path);
    p.with_extension("hmac")
}

/// Wraps the content of an HMAC cache file: the per-page HMACs for a V-App's code section.
#[derive(Debug, Clone)]
pub struct CodeHmacs {
    hmacs: Vec<[u8; 32]>,
}

#[derive(Debug)]
pub enum CodeHmacsLoadError {
    Io(std::io::Error),
    FileTooShort,
    InvalidMagic,
    VappHashMismatch,
    AppIdMismatch,
    InvalidHmacLength,
}

impl std::fmt::Display for CodeHmacsLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error while loading HMAC cache: {err}"),
            Self::FileTooShort => write!(f, "Invalid HMAC cache format: file too short"),
            Self::InvalidMagic => write!(f, "Invalid HMAC cache format: wrong magic bytes"),
            Self::VappHashMismatch => write!(f, "HMAC cache does not match V-App hash"),
            Self::AppIdMismatch => write!(f, "HMAC cache does not match Vanadium app ID"),
            Self::InvalidHmacLength => {
                write!(
                    f,
                    "Invalid HMAC cache format: trailing bytes are not 32-byte aligned"
                )
            }
        }
    }
}

impl std::error::Error for CodeHmacsLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl CodeHmacs {
    /// Creates a new `CodeHmacs` from a vector of per-page HMACs.
    pub fn new(hmacs: Vec<[u8; 32]>) -> Self {
        Self { hmacs }
    }

    /// Returns a reference to the inner HMAC vector.
    pub fn as_slice(&self) -> &[[u8; 32]] {
        &self.hmacs
    }

    /// Consumes `self` and returns the inner HMAC vector.
    pub fn into_inner(self) -> Vec<[u8; 32]> {
        self.hmacs
    }

    /// Loads HMACs from a cache file, validating the magic, `vapp_hash` and `vanadium_app_id`.
    ///
    /// Returns an error if the file can't be read, has wrong format, or has mismatched identifiers.
    pub fn load(
        path: &Path,
        expected_vapp_hash: &[u8; 32],
        expected_app_id: &[u8; 32],
    ) -> Result<Self, CodeHmacsLoadError> {
        let data = std::fs::read(path).map_err(CodeHmacsLoadError::Io)?;

        // Header: 10 (magic) + 32 (vapp_hash) + 32 (app_id) = 74 bytes minimum
        if data.len() < 74 {
            return Err(CodeHmacsLoadError::FileTooShort);
        }

        // Check magic
        if &data[0..10] != HMAC_FILE_MAGIC.as_slice() {
            return Err(CodeHmacsLoadError::InvalidMagic);
        }

        // Check vapp_hash
        if &data[10..42] != expected_vapp_hash {
            return Err(CodeHmacsLoadError::VappHashMismatch);
        }

        // Check vanadium_app_id
        if &data[42..74] != expected_app_id {
            return Err(CodeHmacsLoadError::AppIdMismatch);
        }

        // Remaining bytes must be a multiple of 32
        let hmac_bytes = &data[74..];
        if hmac_bytes.len() % 32 != 0 {
            return Err(CodeHmacsLoadError::InvalidHmacLength);
        }

        let n = hmac_bytes.len() / 32;
        let mut hmacs = Vec::with_capacity(n);
        for i in 0..n {
            let mut hmac = [0u8; 32];
            hmac.copy_from_slice(&hmac_bytes[i * 32..(i + 1) * 32]);
            hmacs.push(hmac);
        }

        Ok(Self { hmacs })
    }

    /// Saves HMACs to a cache file with format:
    ///
    /// `"VAPP_HMAC\0"` (10 bytes) || `vapp_hash` (32 bytes) || `vanadium_app_id` (32 bytes) || N × 32 bytes of HMACs.
    pub fn save(
        &self,
        path: &Path,
        vapp_hash: &[u8; 32],
        vanadium_app_id: &[u8; 32],
    ) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(path)?;
        file.write_all(HMAC_FILE_MAGIC)?;
        file.write_all(vapp_hash)?;
        file.write_all(vanadium_app_id)?;
        for hmac in &self.hmacs {
            file.write_all(hmac)?;
        }
        Ok(())
    }
}
