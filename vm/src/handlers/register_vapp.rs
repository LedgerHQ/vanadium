use crate::{
    hash::Sha256Hasher,
    vapp::{VAppStore, VAppStoreError},
    AppSW, COMM_BUFFER_SIZE,
};
use alloc::vec::Vec;
use common::manifest::Manifest;
use ledger_device_sdk::{
    include_gif,
    nbgl::{Field, NbglGlyph, NbglReview},
};

pub fn handler_register_vapp(
    command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let data_raw = command.get_data();

    let (manifest, rest) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if rest.len() != 0 {
        return Err(AppSW::IncorrectData); // extra data
    }

    manifest.validate().map_err(|_| AppSW::IncorrectData)?; // ensure manifest is valid

    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_64x64.gif", NBGL));
    #[cfg(any(target_os = "apex_p"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_48x48.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_16x16.gif", NBGL));

    let vapp_hash: [u8; 32] = manifest.get_vapp_hash::<Sha256Hasher, 32>();
    let mut vapp_hash_hex = [0u8; 64];
    hex::encode_to_slice(vapp_hash, &mut vapp_hash_hex).unwrap();
    let vapp_hash_hex_str = core::str::from_utf8(&vapp_hash_hex).unwrap();
    let approved = {
        #[cfg(feature = "blind_registration")]
        {
            true
        }

        #[cfg(not(feature = "blind_registration"))]
        {
            NbglReview::new()
                .glyph(&VANADIUM_ICON)
                .light()
                .titles(
                    "Register V-App",
                    "Authorize the execution of this V-App",
                    "Confirm registration",
                )
                .show(&[
                    Field {
                        name: "App name",
                        value: manifest.get_app_name(),
                    },
                    Field {
                        name: "App version",
                        value: manifest.get_app_version(),
                    },
                    Field {
                        name: "Hash",
                        value: vapp_hash_hex_str,
                    },
                ])
        }
    };

    if !approved {
        return Err(AppSW::Deny);
    }

    // Register the V-App in the store
    VAppStore::register(&manifest).map_err(|e| match e {
        VAppStoreError::StoreFull => AppSW::StoreFull,
        VAppStoreError::NameTooLong | VAppStoreError::VersionTooLong => AppSW::IncorrectData,
    })?;

    Ok(Vec::new())
}
