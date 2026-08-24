//! PSBT signing handler.
//!
//! Pipeline: parse the PSBT, run cheap structural analysis ([`analyze`]), spawn the
//! expensive verification as a background task that runs concurrently with the
//! approval UI, show warnings, display the transaction for approval ([`display`]),
//! wait for verification, sign ([`signing`], dispatching to [`musig`] where needed),
//! and respond.

mod analyze;
mod context;
mod display;
mod key_resolution;
mod musig;
mod sighash;
mod signing;

#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

use common::{errors::Error, fastpsbt, message::Response};

use crate::handlers::musig_signing::{self, MusigSigningState};

#[cfg(not(any(test, feature = "autoapprove")))]
use sdk::ux::Icon;

pub async fn handle_sign_psbt(app: &mut sdk::App, psbt: &[u8]) -> Result<Response, Error> {
    app.show_spinner("Processing...");

    let psbt = fastpsbt::Psbt::parse(psbt).map_err(|_| Error::FailedToDeserializePsbt)?;

    // Lightweight analysis: structural validation + extract data for display and verification
    let (summary, deferred_checks) = analyze::analyze_transaction(&psbt)?;

    // Spawn expensive verification (proof-of-registration + script derivation) as a background
    // task so it runs concurrently with the UX flows below.
    let verification_handle = app.spawn_task(async { deferred_checks.verify(&summary).await });

    // Show warnings (runs while verification task progresses in the background)
    if summary.warn_unverified_inputs && !display::display_warning_unverified_inputs(app).await {
        return Err(Error::UserRejected);
        // verification_handle is dropped here → task is cancelled
    }

    let fee = summary.fee();
    if summary.inputs_total_amount >= crate::constants::THRESHOLD_WARN_HIGH_FEES_AMOUNT {
        let fee_percent = fee.saturating_mul(100) / summary.inputs_total_amount;
        if fee_percent >= crate::constants::THRESHOLD_WARN_HIGH_FEES_PERCENT
            && !display::display_warning_high_fee(app, fee_percent).await
        {
            return Err(Error::UserRejected);
        }
    }

    // Display transaction for user approval
    let pairs = display::build_display_pairs(&psbt, &summary)?;
    if !display::display_transaction(app, &pairs).await {
        #[cfg(not(any(test, feature = "autoapprove")))]
        app.show_info(Icon::Failure, "Transaction rejected");

        return Err(Error::UserRejected);
    }

    // Wait for verification to complete (likely already done by now)
    app.await_task("Verifying...", verification_handle)?;

    // All checks passed — sign
    app.show_spinner("Signing transaction...");
    let mut musig_state = MusigSigningState::default();
    let signed = signing::sign_all_inputs(&psbt, &summary, &mut musig_state)?;

    // Persist the round-1 session, if any, only after the signing pass has
    // completed successfully — partial failures must leave no stale session.
    musig_signing::commit(&musig_state)?;

    #[cfg(not(any(test, feature = "autoapprove")))]
    app.show_info(Icon::Success, "Transaction signed");

    Ok(Response::PsbtSigned {
        signatures: signed.signatures,
        musig_pubnonces: signed.musig_pubnonces,
        musig_partial_sigs: signed.musig_partial_sigs,
    })
}
