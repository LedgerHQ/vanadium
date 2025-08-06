use clap::Parser;
use client::TestClient;

use sdk::vanadium_client::client_utils::{create_default_client, ClientType};

mod commands;

mod client;

use std::io::BufRead;

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
    Ux(u8),
    DeviceProp(u32),
    Panic(String),
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

/// Parses a string into a u8 integer.
fn parse_u8(s: &str) -> Result<u8, String> {
    s.parse::<u8>()
        .map_err(|_| "Invalid u8 integer".to_string())
}

/// Parses a string into a u32 integer.
fn parse_u32(s: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| "Invalid u32 integer".to_string())
}

fn parse_command(line: &str) -> Result<CliCommand, String> {
    let mut tokens = line.split_whitespace();
    if let Some(command) = tokens.next() {
        match command {
            "reverse" | "sha256" | "b58enc" => {
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
            "ux" => {
                let arg = tokens
                    .next()
                    .ok_or_else(|| format!("'{}' requires a u8 integer argument", command))?;
                let id = parse_u8(arg).map_err(|e| e.to_string())?;
                Ok(CliCommand::Ux(id))
            }
            "deviceprop" => {
                let arg = tokens
                    .next()
                    .ok_or_else(|| format!("'{}' requires a u32 integer argument", command))?;
                let property_id = parse_u32(arg).map_err(|e| e.to_string())?;
                Ok(CliCommand::DeviceProp(property_id))
            }
            "panic" => {
                // find where the word "panic" ends and the message starts
                let msg = line
                    .find("panic")
                    .map(|i| line[i + 5..].trim())
                    .unwrap_or("");
                Ok(CliCommand::Panic(msg.to_string()))
            }
            _ => Err(format!("Unknown command: '{}'", command)),
        }
    } else {
        Ok(CliCommand::Exit)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "debug")]
    {
        let log_file = std::fs::File::create("debug.log")?;
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
    }

    let args = Args::parse();

    if args.hid && args.native {
        eprintln!("The --native and --hid options are mutually exclusive.");
        std::process::exit(1);
    }

    let client_type = if args.hid {
        ClientType::Hid
    } else if args.native {
        ClientType::Native
    } else {
        ClientType::Tcp
    };
    let mut test_client = TestClient::new(create_default_client("vnd-test", client_type).await?);

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
                CliCommand::Ux(id) => {
                    test_client.ux(id).await?;
                }
                CliCommand::DeviceProp(property) => {
                    let value = test_client.device_props(property).await?;
                    println!("Value for property {}: 0x{:08x}", property, value);
                }
                CliCommand::Panic(msg) => {
                    test_client.panic(&msg).await?;
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
