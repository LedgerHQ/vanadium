use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::linewriter::FileLineWriter;
use crate::transport::{TransportTcp, TransportWrapper};
use crate::vanadium_client::{VAppTransport, VanadiumAppClient};

pub struct TestSetup<C> {
    pub client: C,
    pub transport_tcp: Arc<TransportTcp>,
    child: Child,
    log_file: File,
}

impl<C> TestSetup<C> {
    pub async fn new<F, Fut>(speculos_binary: &str, create_client: F) -> Self
    where
        F: FnOnce(Arc<TransportWrapper>) -> Fut,
        Fut: std::future::Future<Output = C>,
    {
        let (child, transport_tcp) = spawn_speculos_and_transport(speculos_binary).await;

        let transport = Arc::new(TransportWrapper::new(transport_tcp.clone()));

        let client = create_client(transport).await;

        // Create log file and write test name
        let mut log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("test.log")
            .expect("Failed to open test.log");

        writeln!(
            log_file,
            "=== Test: {} ===",
            std::thread::current().name().unwrap_or("unknown_test")
        )
        .unwrap();

        TestSetup {
            client,
            transport_tcp,
            child,
            log_file,
        }
    }
}

/// Helper function to:
/// 1) Spawn speculos
/// 2) Poll for a running TCP transport (readiness)
/// 3) If speculos dies prematurely, relaunch once
async fn spawn_speculos_and_transport(vanadium_binary: &str) -> (Child, Arc<TransportTcp>) {
    const MAX_LAUNCH_ATTEMPTS: usize = 10;
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
        let mut transport_tcp: Option<Arc<TransportTcp>> = None;

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
                    // If we succeed, store the TransportTcp instance directly
                    transport_tcp = Some(Arc::new(tcp));
                    break;
                }
                Err(_) => {
                    // Wait a little before retrying
                    sleep(Duration::from_millis(500));
                }
            }
        }

        // Did we succeed in getting a transport?
        if let Some(t) = transport_tcp {
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

impl<C> Drop for TestSetup<C> {
    fn drop(&mut self) {
        // Write the number of exchanges, amount sent and amount received to the log file
        let _ = writeln!(
            self.log_file,
            "Total exchanges: {}",
            self.transport_tcp.total_exchanges()
        );
        let _ = writeln!(
            self.log_file,
            "Total sent: {}",
            self.transport_tcp.total_sent()
        );
        let _ = writeln!(
            self.log_file,
            "Total received: {}",
            self.transport_tcp.total_received()
        );

        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub async fn setup_test<C, F>(
    vanadium_binary: &str,
    vapp_binary: &str,
    create_client: F,
) -> TestSetup<C>
where
    F: FnOnce(Box<dyn VAppTransport + Send + Sync>) -> C,
{
    TestSetup::new(vanadium_binary, |transport| async move {
        let print_writer = Box::new(FileLineWriter::new("print.log", true, true));
        let (vanadium_client, _) =
            VanadiumAppClient::new(vapp_binary, transport, None, print_writer)
                .await
                .expect("Failed to create client");

        create_client(Box::new(vanadium_client))
    })
    .await
}
