use std::process::{Child, Command};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use vnd_sadik_client::SadikClient;

use sdk::{
    transport::{Transport, TransportTcp, TransportWrapper},
    vanadium_client::VanadiumAppClient,
};

pub struct TestSetup {
    pub client: SadikClient,
    child: Child,
}

impl TestSetup {
    async fn new() -> Self {
        let vanadium_binary = std::env::var("VANADIUM_BINARY")
            .unwrap_or_else(|_| "../../../vm/build/nanos2/bin/app.elf".to_string());
        let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
            "../app/target/riscv32im-unknown-none-elf/release/vnd-sadik".to_string()
        });

        let (child, transport) = spawn_speculos_and_transport(&vanadium_binary).await;

        let (vanadium_client, _) = VanadiumAppClient::new(&vapp_binary, transport, None)
            .await
            .expect("Failed to create client");

        let client = SadikClient::new(Box::new(vanadium_client));

        TestSetup { client, child }
    }
}

impl Drop for TestSetup {
    fn drop(&mut self) {
        self.child.kill().expect("Failed to kill speculos process");
        self.child
            .wait()
            .expect("Failed to wait on speculos process");
    }
}

/// Helper function to:
/// 1) Spawn speculos
/// 2) Poll for a running TCP transport (readiness)
/// 3) If speculos dies prematurely, relaunch once
async fn spawn_speculos_and_transport(
    vanadium_binary: &str,
) -> (
    Child,
    Arc<dyn Transport<Error = Box<dyn std::error::Error + Send + Sync>> + Send + Sync>,
) {
    const MAX_LAUNCH_ATTEMPTS: usize = 2;
    const MAX_POLL_ATTEMPTS: usize = 5;

    let mut launch_attempts = 0;

    loop {
        // --- 1) Spawn speculos ---
        let mut child = Command::new("speculos")
            .arg(vanadium_binary)
            .arg("--display")
            .arg("headless")
            .spawn()
            .expect("Failed to spawn speculos process");

        // --- 2) Poll for readiness ---
        let mut transport: Option<Arc<_>> = None;

        for _ in 0..MAX_POLL_ATTEMPTS {
            // Check if speculos died
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!(
                    "Speculos exited early with status: {}",
                    status.code().unwrap_or(-1)
                );
                break; // break out of poll loop, we'll relaunch if attempts remain
            }

            // If it's still alive, try to connect
            match TransportTcp::new().await {
                Ok(tcp) => {
                    // If we succeed, wrap it up and return
                    transport = Some(Arc::new(TransportWrapper::new(Arc::new(tcp))));
                    break;
                }
                Err(_) => {
                    // Wait a little before retrying
                    sleep(Duration::from_millis(500));
                }
            }
        }

        // Did we succeed in getting a transport?
        if let Some(t) = transport {
            // Return on success
            return (child, t);
        }

        // Otherwise, kill child and try again if we have attempts left
        let _ = child.kill();
        let _ = child.wait();

        launch_attempts += 1;
        if launch_attempts >= MAX_LAUNCH_ATTEMPTS {
            panic!(
                "Speculos did not become ready after {} launch attempts.",
                launch_attempts
            );
        }
        eprintln!(
            "Retrying speculos launch (attempt {})...",
            launch_attempts + 1
        );
    }
}

pub async fn setup() -> TestSetup {
    TestSetup::new().await
}
