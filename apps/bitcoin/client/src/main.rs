use clap::Parser;
use client::BitcoinClient;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;

use sdk::transport::{Transport, TransportHID, TransportTcp, TransportWrapper};
use sdk::vanadium_client::{NativeAppClient, VanadiumAppClient};

mod client;

use std::io::{self, Write};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "Vanadium", about = "Run a V-App on Vanadium")]
struct Args {
    /// Path to the ELF file of the V-App (if not the default one)
    app: Option<String>,

    /// Use the HID interface for a real device, instead of Speculos
    #[arg(long, group = "interface")]
    hid: bool,

    /// Use the native interface
    #[arg(long, group = "interface")]
    native: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let default_app_path = if args.native {
        "../app/target/x86_64-unknown-linux-gnu/release/vnd-bitcoin"
    } else {
        "../app/target/riscv32i-unknown-none-elf/release/vnd-bitcoin"
    };

    let app_path_str = args.app.unwrap_or(default_app_path.to_string());

    let mut bitcoin_client = if args.native {
        BitcoinClient::new(Box::new(
            NativeAppClient::new(&app_path_str)
                .await
                .map_err(|_| "Failed to create client")?,
        ))
    } else {
        let transport_raw: Arc<
            dyn Transport<Error = Box<dyn std::error::Error + Send + Sync>> + Send + Sync,
        > = if args.hid {
            Arc::new(TransportHID::new(
                TransportNativeHID::new(
                    &HidApi::new().expect("Unable to get connect to the device"),
                )
                .unwrap(),
            ))
        } else {
            Arc::new(
                TransportTcp::new()
                    .await
                    .expect("Unable to get TCP transport. Is speculos running?"),
            )
        };
        let transport = TransportWrapper::new(transport_raw.clone());

        let (client, _) = VanadiumAppClient::new(&app_path_str, Arc::new(transport), None)
            .await
            .map_err(|_| "Failed to create client")?;

        BitcoinClient::new(Box::new(client))
    };

    println!(
        "Master fingerprint: {:08x}",
        bitcoin_client.get_master_fingerprint().await?
    );

    print!("Please enter some text: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    println!("You entered: {}", input.trim());

    bitcoin_client.exit().await?;

    Ok(())
}
