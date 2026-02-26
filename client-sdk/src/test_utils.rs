use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::linewriter::FileLineWriter;
use crate::transport::{TransportTcp, TransportWrapper};
use crate::vanadium_client::{NativeAppClient, VAppTransport, VanadiumAppClient};

pub struct TestSetup<C> {
    pub client: C,
    /// Only present when running via Speculos (used for metrics logging).
    pub transport_tcp: Option<Arc<TransportTcp>>,
    /// The child process — either Speculos or a native V-App binary.
    child: Child,
    log_file: File,
    /// Temporary storage file created for native V-App tests (cleaned up on drop).
    storage_file: Option<PathBuf>,
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
            transport_tcp: Some(transport_tcp),
            child,
            log_file,
            storage_file: None,
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
        // Attempt to write transport metrics (only available for Speculos)
        if let Some(ref transport_tcp) = self.transport_tcp {
            if let Err(e) = writeln!(
                self.log_file,
                "Total exchanges: {} | Total sent: {} | Total received: {}",
                transport_tcp.total_exchanges(),
                transport_tcp.total_sent(),
                transport_tcp.total_received()
            ) {
                eprintln!("Failed writing metrics: {e}");
            }
        }

        // Check if child process already exited
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let _ = writeln!(
                    self.log_file,
                    "Child process already exited (code={:?}).",
                    status.code()
                );
            }
            Ok(None) => {
                if let Err(e) = self.child.kill() {
                    eprintln!("Failed to kill child process: {e}");
                }
                let _ = self.child.wait();
                let _ = writeln!(self.log_file, "Child process killed.");
            }
            Err(e) => {
                eprintln!("Error querying child process status: {e}");
            }
        }

        // Clean up temporary storage file
        if let Some(ref path) = self.storage_file {
            let _ = fs::remove_file(path);
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
    init_test_logger();

    TestSetup::new(vanadium_binary, |transport| async move {
        let print_writer = Box::new(FileLineWriter::new("print.log", true, true));
        let vanadium_client =
            VanadiumAppClient::with_vapp(vapp_binary, transport, print_writer, false)
                .await
                .expect(&format!(
                    "Failed to create client for vapp binary: {}",
                    vapp_binary
                ));

        create_client(Box::new(vanadium_client))
    })
    .await
}

/// Spawn a natively-compiled V-App binary as a child process, connect via
/// [`NativeAppClient`], and build the application-specific client.
///
/// The V-App binary is started with `VAPP_ADDRESS=127.0.0.1:<port>` where
/// `<port>` is a randomly chosen free port.  The function polls until the
/// V-App is accepting connections, retrying both the connection and the
/// process launch if necessary.
///
/// # Example
///
/// ```rust,ignore
/// let setup = setup_native_test("../app/target/debug/vnd-sadik", |transport| {
///     SadikClient::new(transport)
/// })
/// .await;
/// ```
pub async fn setup_native_test<C, F>(vapp_binary: &str, create_client: F) -> TestSetup<C>
where
    F: FnOnce(Box<dyn VAppTransport + Send + Sync>) -> C,
{
    init_test_logger();

    let (child, native_client, storage_file) = spawn_native_vapp_and_connect(vapp_binary).await;

    let client = create_client(Box::new(native_client));

    // Create log file and write test name
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("test.log")
        .expect("Failed to open test.log");

    writeln!(
        log_file,
        "=== Test (native): {} ===",
        std::thread::current().name().unwrap_or("unknown_test")
    )
    .unwrap();

    TestSetup {
        client,
        transport_tcp: None,
        child,
        log_file,
        storage_file: Some(storage_file),
    }
}

/// Spawn a native V-App binary and poll until a [`NativeAppClient`] can
/// connect to it.
async fn spawn_native_vapp_and_connect(vapp_binary: &str) -> (Child, NativeAppClient, PathBuf) {
    const MAX_LAUNCH_ATTEMPTS: usize = 10;
    const MAX_POLL_ATTEMPTS: usize = 10;

    let mut launch_attempts = 0;

    // Each test instance gets its own storage file to avoid cross-test contamination.
    let storage_file = PathBuf::from(format!("vapp_storage_{}.dat", std::process::id()));

    loop {
        let port =
            get_random_free_port().expect("Failed to bind to an ephemeral port for native V-App");

        let addr = format!("127.0.0.1:{port}");

        // Spawn the native V-App with VAPP_ADDRESS set to the chosen port
        let stdout_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("native_vapp_stdout.log")
            .expect("Failed to open native_vapp_stdout.log");

        let stderr_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("native_vapp_stderr.log")
            .expect("Failed to open native_vapp_stderr.log");

        let mut child = Command::new(vapp_binary)
            .env("VAPP_ADDRESS", &addr)
            .env("VAPP_STORAGE_FILE", &storage_file)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn native V-App ({vapp_binary}): {e}"));

        // Poll for readiness
        let mut connected_client: Option<NativeAppClient> = None;

        for _ in 0..MAX_POLL_ATTEMPTS {
            // Check if the process died
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!(
                    "Native V-App exited early with status: {}",
                    status.code().unwrap_or(-1)
                );
                break;
            }

            let print_writer: Box<dyn std::io::Write + Send + Sync> =
                Box::new(FileLineWriter::new("print.log", true, true));

            match NativeAppClient::new(&addr, print_writer).await {
                Ok(client) => {
                    connected_client = Some(client);
                    break;
                }
                Err(_) => {
                    sleep(Duration::from_millis(500)).await;
                }
            }
        }

        if let Some(client) = connected_client {
            return (child, client, storage_file);
        }

        // Kill and retry
        let _ = child.kill();
        let _ = child.wait();

        launch_attempts += 1;
        if launch_attempts >= MAX_LAUNCH_ATTEMPTS {
            panic!("Native V-App did not become ready after {launch_attempts} launch attempts.");
        }
        eprintln!(
            "Retrying native V-App launch (attempt {})...",
            launch_attempts + 1
        );
    }
}

/// Initialize the env_logger for test output (no-op without the `debug` feature).
fn init_test_logger() {
    #[cfg(feature = "debug")]
    {
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
}
