use clap::Parser;
use vnd_template_client::Client;

use sdk::vanadium_client::client_utils::{create_default_client, ClientType};
use std::io::BufRead;

#[derive(Parser)]
#[command(name = "Template", about = "Run the Template V-App on Vanadium")]
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

    let client_type = if args.hid {
        ClientType::Hid
    } else if args.native {
        ClientType::Native
    } else {
        ClientType::Tcp
    };
    let mut client = Client::new(create_default_client("{{project-app-crate}}", client_type, None).await?);

    loop {
        println!("Enter the message to be signed (or empty to exit):");
        let mut msg = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut msg)
            .expect("Failed to read line");

        let msg = msg.trim().as_bytes();
        if msg.is_empty() {
            break;
        }

        let sig = client.sign_message(msg).await?;

        if sig.is_empty() {
            println!("Signature rejected");
        } else {
            let sig_hex = sig.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            println!("Received signature: {}", sig_hex);
        }
    }
    let exit_code = client.exit().await?;
    println!("V-App exited with code: {}", exit_code);
    Ok(())
}
