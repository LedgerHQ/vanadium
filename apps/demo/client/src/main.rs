use clap::Parser;
use vnd_demo_client::DemoClient;

use sdk::vanadium_client::client_utils::{create_default_client, ClientType};

use std::io::BufRead;

#[derive(Parser)]
#[command(name = "Demo", about = "Run the Demo V-App on Vanadium")]
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
    let mut demo_client =
        DemoClient::new(create_default_client("vnd-demo", client_type, None).await?);

    loop {
        println!("Say something: ");

        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .expect("Failed to read line");

        if line.trim().is_empty() {
            println!("Exiting...");
            let exit_code = demo_client.exit().await?;
            println!("App exited with code {}", exit_code);
            break;
        }

        let response = demo_client.echo(line.trim().as_bytes()).await?;

        println!(
            "Response: {}\n",
            String::from_utf8(response).expect("Invalid UTF-8 response")
        );
    }
    Ok(())
}
