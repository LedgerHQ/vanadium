use include_gif::include_gif;
use ledger_device_sdk::nbgl::NbglGlyph;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

use crate::io::Comm;

pub fn ui_menu_main(_: &mut Comm) -> NbglHomeAndSettings {
    // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("vanadium_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("vanadium_16x16.gif", NBGL));

    // Display the home screen.
    NbglHomeAndSettings::new()
        .glyph(&VANADIUM_ICON)
        .tagline("Unlimited power\nfor your apps\n(developer preview)")
        .infos(
            "Vanadium",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        )
}
