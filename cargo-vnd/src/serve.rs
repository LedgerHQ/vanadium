use client_sdk::linewriter::FileLineWriter;
use client_sdk::vanadium_client::client_utils::{
    ClientType, ClientUtilsError, create_hid_client, create_native_client, create_tcp_client,
};
use client_sdk::vanadium_client::{VAppExecutionError, VAppTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Read a length-prefixed message from the TCP stream.
/// Returns `None` if the connection was closed.
async fn read_message(
    stream: &mut tokio::net::TcpStream,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::UnexpectedEof
                || e.kind() == std::io::ErrorKind::ConnectionReset =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write a length-prefixed message to the TCP stream.
async fn write_message(
    stream: &mut tokio::net::TcpStream,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn create_vapp_client(
    elf_path: &str,
    client_type: ClientType,
    use_hmacs: bool,
) -> Result<Box<dyn VAppTransport + Send>, ClientUtilsError> {
    let make_print_writer = || -> Option<Box<dyn std::io::Write + Send + Sync>> {
        Some(Box::new(FileLineWriter::new("print.log", true, true)))
    };

    match client_type {
        ClientType::Native => create_native_client(None, make_print_writer()).await,
        ClientType::Tcp => create_tcp_client(elf_path, make_print_writer(), use_hmacs).await,
        ClientType::Hid => create_hid_client(elf_path, make_print_writer(), use_hmacs).await,
        ClientType::Any => {
            // No flag specified: try HID, then Speculos, then native
            eprintln!("No device flag specified, trying HID...");
            match create_hid_client(elf_path, make_print_writer(), use_hmacs).await {
                Ok(client) => {
                    eprintln!("Connected via HID.");
                    Ok(client)
                }
                Err(e) => {
                    eprintln!("HID failed ({e}), trying Speculos...");
                    match create_tcp_client(elf_path, make_print_writer(), use_hmacs).await {
                        Ok(client) => {
                            eprintln!("Connected via Speculos.");
                            Ok(client)
                        }
                        Err(e) => {
                            eprintln!("Speculos failed ({e}), trying native...");
                            create_native_client(None, make_print_writer()).await
                        }
                    }
                }
            }
        }
        ClientType::Standalone => {
            panic!(
                "Standalone client is only supported in the client-sdk to connect to this server!"
            )
        }
    }
}

async fn handle_client(
    vapp: &mut Box<dyn VAppTransport + Send>,
    stream: &mut tokio::net::TcpStream,
) {
    loop {
        let msg = match read_message(stream).await {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                eprintln!("Client disconnected.");
                return;
            }
            Err(e) => {
                eprintln!("Error reading from client: {e}");
                return;
            }
        };

        match vapp.send_message(&msg).await {
            Ok(resp) => {
                if let Err(e) = write_message(stream, &resp).await {
                    eprintln!("Error writing to client: {e}");
                    return;
                }
            }
            Err(VAppExecutionError::AppExited(code)) => {
                eprintln!("V-App exited with status {code}");
                return;
            }
            Err(VAppExecutionError::AppPanicked(msg)) => {
                eprintln!("V-App panicked: {msg}");
                return;
            }
            Err(e) => {
                eprintln!("V-App error: {e}");
                return;
            }
        }
    }
}

pub fn run(
    elf_path: String,
    port: u16,
    client_type: ClientType,
    use_hmacs: bool,
) -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            eprintln!("Connecting to V-App...");
            let mut vapp = create_vapp_client(&elf_path, client_type, use_hmacs)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create V-App client: {e}"))?;

            let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
            eprintln!("Listening on 127.0.0.1:{}", port);

            // Accept one connection at a time (V-App is single-threaded)
            loop {
                let (mut stream, addr) = listener.accept().await?;
                eprintln!("Client connected from {addr}");
                handle_client(&mut vapp, &mut stream).await;
                eprintln!("Ready for new connection.");
            }
        })
}
