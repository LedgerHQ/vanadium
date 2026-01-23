use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

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

// gets a random free port assigned by the OS, then drop the listener and return the port number
fn get_random_free_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Helper function to:
/// 1) Spawn speculos, binding to a random free port
/// 2) Poll for a running TCP transport (readiness)
/// 3) If speculos dies prematurely, relaunch once
async fn spawn_speculos_and_transport(vanadium_binary: &str) -> (Child, Arc<TransportTcp>) {
    const MAX_LAUNCH_ATTEMPTS: usize = 10;
    const MAX_POLL_ATTEMPTS: usize = 5;

    let mut launch_attempts = 0;

    loop {
        // Pick a random free port by binding to port 0 then dropping the listener ---
        let port = get_random_free_port()
            .expect("Failed to bind to an ephemeral port to select APDU port");

        // --- 1) Spawn speculos on that port ---
        // Create log files for speculos outputs
        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("speculos_stdout.log")
            .expect("Failed to open speculos_stdout.log");

        let stderr_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("speculos_stderr.log")
            .expect("Failed to open speculos_stderr.log");

        let mut child = Command::new("speculos")
            .arg(vanadium_binary)
            .arg("--display")
            .arg("headless")
            .arg("--apdu-port")
            .arg(port.to_string())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .expect("Failed to spawn speculos process");

        // --- 2) Poll for readiness ---
        let mut transport_tcp: Option<Arc<TransportTcp>> = None;
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

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
            match TransportTcp::new(socket_addr).await {
                Ok(tcp) => {
                    transport_tcp = Some(Arc::new(tcp));
                    break;
                }
                Err(_) => {
                    // Wait a little before retrying
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Did we succeed in getting a transport?
        if let Some(t) = transport_tcp {
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
        // Attempt to write metrics
        if let Err(e) = writeln!(
            self.log_file,
            "Total exchanges: {} | Total sent: {} | Total received: {}",
            self.transport_tcp.total_exchanges(),
            self.transport_tcp.total_sent(),
            self.transport_tcp.total_received()
        ) {
            eprintln!("Failed writing metrics: {e}");
        }

        // Check if process already exited
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let _ = writeln!(
                    self.log_file,
                    "Speculos already exited (code={:?}).",
                    status.code()
                );
            }
            Ok(None) => {
                if let Err(e) = self.child.kill() {
                    eprintln!("Failed to kill speculos: {e}");
                }
                let _ = self.child.wait();
                let _ = writeln!(self.log_file, "Speculos killed.");
            }
            Err(e) => {
                eprintln!("Error querying speculos status: {e}");
            }
        }
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
    // Initialize logger for tests (ignore error if already initialized)
    #[cfg(feature = "debug")]
    {
        // Open/create test.log in append mode for logging
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("test.log")
            .expect("Failed to open test.log for logging");

        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .try_init();
    }

    TestSetup::new(vanadium_binary, |transport| async move {
        let print_writer = Box::new(FileLineWriter::new("print.log", true, true));
        let vanadium_client =
            VanadiumAppClient::new(vapp_binary, transport, print_writer)
                .await
                .expect(&format!(
                    "Failed to create client for vapp binary: {}",
                    vapp_binary
                ));

        create_client(Box::new(vanadium_client))
    })
    .await
}
