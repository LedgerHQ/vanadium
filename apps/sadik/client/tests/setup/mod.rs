//! Starts the Sadik V-App, either on Speculos or natively, for the integration tests.

use sdk::test_utils::TestSetup;

use vnd_sadik_client::SadikClient;

#[cfg(feature = "speculos-tests")]
pub async fn setup() -> TestSetup<SadikClient> {
    use sdk::test_utils::setup_test;

    let vanadium_binary = std::env::var("VANADIUM_BINARY")
        .unwrap_or_else(|_| "../../../vm/target/flex/release/app-vanadium".to_string());
    let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
        "../app/target/riscv32imac-unknown-none-elf/release/vnd-sadik".to_string()
    });
    setup_test(&vanadium_binary, &vapp_binary, |transport| {
        SadikClient::new(transport)
    })
    .await
}

#[cfg(feature = "native-tests")]
pub async fn setup() -> TestSetup<SadikClient> {
    use sdk::test_utils::setup_native_test;

    let vapp_binary = std::env::var("VAPP_BINARY")
        .unwrap_or_else(|_| "../app/target/release/vnd-sadik".to_string());
    setup_native_test(&vapp_binary, |transport| SadikClient::new(transport)).await
}
