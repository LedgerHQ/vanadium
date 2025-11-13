use crate::handlers::lib::vapp::get_vapp_hmac;
use crate::{hash::Sha256Hasher, AppSW, COMM_BUFFER_SIZE};
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

    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_64x64.gif", NBGL));
    #[cfg(any(target_os = "apex_p"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_48x48.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_16x16.gif", NBGL));

    let vapp_hash = manifest.get_vapp_hash::<Sha256Hasher, 32>();
    let vapp_hash_hex = hex::encode(vapp_hash);
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
                        value: vapp_hash_hex.as_str(),
                    },
                ])
        }
    };

    if !approved {
        return Err(AppSW::Deny);
    }

    let vapp_hmac = get_vapp_hmac(&manifest);

    Ok(vapp_hmac.to_vec())
}
