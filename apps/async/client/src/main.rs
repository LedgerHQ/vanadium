use clap::Parser;
use vnd_async_client::Client;

use sdk::{
    linewriter::FileLineWriter,
    vanadium_client::client_utils::{create_default_client, ClientType},
};
use std::io::BufRead;

#[derive(Parser)]
#[command(name = "Async", about = "Run the Async V-App on Vanadium")]
struct Args {
    /// Path to the ELF file of the V-App (if not the default one)
    app: Option<String>,

    /// Use the HID interface for a real device, instead of Speculos
    #[arg(long, group = "interface")]
    hid: bool,

    /// Use Speculos emulator interface
    #[arg(long, group = "interface")]
    sym: bool,

    /// Use the native interface
    #[arg(long, group = "interface")]
    native: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let client_type = if args.hid {
        ClientType::Hid
    } else if args.native {
        ClientType::Native
    } else if args.sym {
        ClientType::Tcp
    } else {
        ClientType::Any
    };
    let print_writer = Box::new(FileLineWriter::new("print.log", true, true));
    let mut client = Client::new(
        create_default_client("vnd-async", client_type, Some(print_writer), false).await?,
    );

    loop {
        println!("Enter '<repetitions> sync|async' (or empty line to quit):");
        let mut msg = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut msg)
            .expect("Failed to read line");

        let msg = msg.trim().to_string();
        if msg.is_empty() {
            break;
        }

        let mut parts = msg.splitn(2, ' ');
        let n: u32 = match parts.next().unwrap_or("").parse() {
            Ok(num) => num,
            Err(_) => {
                println!("Invalid input. Expected format: '<number> sync|async'");
                continue;
            }
        };
        let mode = parts.next().unwrap_or("").trim();

        let _response = if mode.eq_ignore_ascii_case("sync") {
            client.do_work_sync(n).await?
        } else if mode.eq_ignore_ascii_case("async") {
            client.do_work_async(n).await?
        } else {
            println!("Invalid mode '{}'. Expected 'sync' or 'async'.", mode);
            continue;
        };
    }
    let exit_code = client.exit().await?;
    println!("V-App exited with code: {}", exit_code);
    Ok(())
}
