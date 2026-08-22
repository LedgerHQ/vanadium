//! The signing programs shipped in `apps/bitcoin/assets/signing_policies`,
//! embedded verbatim so that tests exercise exactly the bytes the CLI would send
//! (and therefore exactly the same program hashes).
//!
//! Editing one of those files changes its hash, and thus the derivation path of
//! any key bound to it; nothing here hardcodes a hash, so the tests follow along
//! automatically.

macro_rules! shipped_policies {
    ($(($konst:ident, $file:literal)),* $(,)?) => {
        $(
            #[doc = concat!("Contents of `assets/signing_policies/", $file, "`.")]
            pub const $konst: &[u8] =
                include_bytes!(concat!("../../../assets/signing_policies/", $file));
        )*

        /// Every shipped program, as `(file name, source)` pairs.
        pub const ALL: &[(&str, &[u8])] = &[$(($file, $konst)),*];
    };
}

shipped_policies![
    (ALWAYS_APPROVE, "always-approve.plc"),
    (CONSOLIDATION_ONLY, "consolidation-only.plc"),
    (FEE_CAP, "fee-cap.plc"),
    (NEVER_SIGN, "never-sign.plc"),
    (SELF_TRANSFER_ONLY, "self-transfer-only.plc"),
    (SINGLE_RECIPIENT, "single-recipient.plc"),
    (SMALL_SPEND_AUTO_APPROVE, "small-spend-auto-approve.plc"),
    (SPENDING_LIMITS, "spending-limits.plc"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::validate_policy;
    use common::psbt::signing_policy::{SigningPolicyEntry, ENGINE_ID_PROGRAM};

    /// Every program we ship as an example must compile on the device.
    #[test]
    fn shipped_policies_compile() {
        for (name, script) in ALL {
            let entry = SigningPolicyEntry {
                hash: [0; 32],
                engine_id: ENGINE_ID_PROGRAM,
                engine_version: 0,
                script,
            };
            assert_eq!(validate_policy(&entry), Ok(()), "{name} must compile");
        }
    }
}
