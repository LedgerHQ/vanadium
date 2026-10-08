//! Conformance tests for the ECALLs' own contract.
//!
//! Every test makes raw ECALLs through the Sadik V-App, bypassing the SDK's wrappers, and checks
//! the exact status and output. The same expectations run against the native target
//! (`--features native-tests`) and against the VM on Speculos (`--features speculos-tests`), so
//! passing on both means that the two implementations agree. An ECALL must never kill the V-App
//! on invalid input: it returns 0.
#![cfg(any(feature = "speculos-tests", feature = "native-tests"))]

use common::{RawEcall, RawEcallResult};
use vnd_sadik_client::SadikClient;

mod setup;
use setup::setup;

/// Makes `call`, failing the test if the V-App does not survive it.
async fn ecall(client: &mut SadikClient, call: RawEcall) -> RawEcallResult {
    match client.raw_ecall(call.clone()).await {
        Ok(res) => res,
        Err(e) => panic!("the V-App did not survive {call:?}: {e}"),
    }
}

#[tokio::test]
async fn test_raw_ecall_harness() {
    let mut setup = setup().await;

    let res = ecall(
        &mut setup.client,
        RawEcall::BnModm {
            n: vec![0, 0, 0, 11],
            m: vec![0, 0, 0, 7],
        },
    )
    .await;
    assert_eq!(
        res,
        RawEcallResult {
            status: 1,
            output: vec![0, 0, 0, 4]
        }
    );
}
