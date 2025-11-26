use ledger_device_sdk::{include_gif, io::Comm, nbgl::NbglHomeAndSettings};

use ledger_device_sdk::nbgl::NbglGlyph;

pub fn ui_menu_main(_: &mut Comm<{ crate::COMM_BUFFER_SIZE }>) -> NbglHomeAndSettings {
    // Load glyph from 64x64 4bpp gif file with include_gif macro. Creates an NBGL compatible glyph.
    #[cfg(target_os = "apex_p")]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_48x48_bw.gif", NBGL));
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const VANADIUM_ICON: NbglGlyph =
        NbglGlyph::from_include(include_gif!("icons/vanadium_14x14.gif", NBGL));

    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const TAGLINE: &str = "Vanadium\nDeveloper preview\nOnly use a test seed";

    #[cfg(any(target_os = "flex", target_os = "stax", target_os = "apex_p"))]
    const TAGLINE: &str = "\nDeveloper preview\nOnly use a test seed";

    // Display the home screen.
    NbglHomeAndSettings::new()
        .glyph(&VANADIUM_ICON)
        .tagline(TAGLINE)
        .infos(
            "Vanadium",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_AUTHORS"),
        )
}
