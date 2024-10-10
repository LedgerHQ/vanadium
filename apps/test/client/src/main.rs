use clap::Parser;
use client::TestClient;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;

use sdk::transport::{Transport, TransportHID, TransportTcp, TransportWrapper};
use sdk::vanadium_client::{NativeAppClient, VanadiumAppClient};

mod commands;

mod client;

use std::io::BufRead;
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

enum CliCommand {
    Reverse(Vec<u8>),
    AddNumbers(u32),
    Sha256(Vec<u8>),
    B58Enc(Vec<u8>),
    NPrimes(u32),
    Exit,
}

/// Parses a hex-encoded string into a vector of bytes.
fn parse_hex_buffer(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string has an odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex character at position {}", i))
        })
        .collect()
}

/// Parses a string into a u32 integer.
fn parse_u32(s: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| "Invalid u32 integer".to_string())
}

fn parse_command(line: &str) -> Result<CliCommand, String> {
    let mut tokens = line.trim().split_whitespace();
    if let Some(command) = tokens.next() {
        match command {
            "reverse" | "sha256" | "b58enc" | "b58encode" => {
                let arg = tokens.next().unwrap_or("");
                let buffer = parse_hex_buffer(arg).map_err(|e| e.to_string())?;
                match command {
                    "reverse" => Ok(CliCommand::Reverse(buffer)),
                    "sha256" => Ok(CliCommand::Sha256(buffer)),
                    "b58enc" => Ok(CliCommand::B58Enc(buffer)),
                    _ => unreachable!(),
                }
            }
            "addnumbers" | "nprimes" => {
                let arg = tokens
                    .next()
                    .ok_or_else(|| format!("'{}' requires a u32 integer argument", command))?;
                let number = parse_u32(arg).map_err(|e| e.to_string())?;
                match command {
                    "addnumbers" => Ok(CliCommand::AddNumbers(number)),
                    "nprimes" => Ok(CliCommand::NPrimes(number)),
                    _ => unreachable!(),
                }
            }
            _ => Err(format!("Unknown command: '{}'", command)),
        }
    } else {
        return Ok(CliCommand::Exit);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    let default_app_path = if args.native {
        "../app/target/x86_64-unknown-linux-gnu/release/vnd-test"
    } else {
        "../app/target/riscv32i-unknown-none-elf/release/vnd-test"
    };

    let app_path_str = args.app.unwrap_or(default_app_path.to_string());

    let mut test_client = if args.native {
        TestClient::new(Box::new(NativeAppClient::new(&app_path_str).await?))
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

        TestClient::new(Box::new(
            VanadiumAppClient::new(&app_path_str, Arc::new(transport)).await?,
        ))
    };

    loop {
        println!("Enter a command:");

        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("Failed to read line");

        match parse_command(&line) {
            Ok(cmd) => match cmd {
                CliCommand::Reverse(arg) => {
                    println!("{}", hex::encode(test_client.reverse(&arg).await?));
                }
                CliCommand::AddNumbers(number) => {
                    println!("{}", test_client.add_numbers(number).await?);
                }
                CliCommand::Sha256(arg) => {
                    println!("{}", hex::encode(test_client.sha256(&arg).await?));
                }
                CliCommand::B58Enc(arg) => {
                    println!("{}", hex::encode(test_client.b58enc(&arg).await?));
                }
                CliCommand::NPrimes(n) => {
                    println!("{}", test_client.nprimes(n).await?);
                }
                CliCommand::Exit => {
                    let status = test_client.exit().await?;
                    if status != 0 {
                        std::process::exit(status);
                    }
                    break;
                }
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    Ok(())
}
