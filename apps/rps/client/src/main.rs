// Alice (client)                                Bob (V-App)
//
// choose m_a <-- {0, 1, 2}
// r_a <$-- {0, 1}^256
// c_a = SHA256(m_a || r_a)
//
//                            c_a
//                |---------COMMIT--------->
//
//                                             Choose m_b <-- {0, 1, 2}
//
//                            m_b
//                <---------BOB_MOVE-------|
//
//
//                         m_a, r_a
//                |---------REVEAL--------->
//                                              Verify that c_a = SHA256(m_a || r_a)
//                                              Compute winner
//

use clap::Parser;
use sha2::Digest;
use vnd_rps_client::RPSClient;

use sdk::vanadium_client::client_utils::{create_default_client, ClientType};

use core::panic;
use std::io::BufRead;

fn display_move(move_num: u8) -> &'static str {
    match move_num {
        0 => "Rock 🪨",
        1 => "Paper ✋",
        2 => "Scissors ✂️",
        _ => panic!("Invalid move number: {}", move_num),
    }
}

fn parse_winner(winner: u8) -> &'static str {
    match winner {
        0 => "Tie 😐",
        1 => "Bob wins 🤕",
        2 => "Alice wins 😀",
        _ => panic!("Invalid winner value"),
    }
}

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

    let client_type = if args.hid {
        ClientType::Hid
    } else if args.native {
        ClientType::Native
    } else {
        ClientType::Tcp
    };
    let mut demo_client =
        RPSClient::new(create_default_client("vnd-rps", client_type, None).await?);

    println!("Playing as Alice");

    loop {
        println!("Choose the move (R)ock, (P)aper, (S)cissors. Leave empty to exit:");
        let m_a = loop {
            let mut move_choice = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut move_choice)
                .expect("Failed to read line");
            let move_choice = move_choice.trim().to_uppercase();
            match move_choice.as_str() {
                "R" => break 0,
                "P" => break 1,
                "S" => break 2,
                "" => break 0xff, // signal to exit
                _ => {
                    println!("Invalid choice. Please choose R, P, or S.");
                    continue;
                }
            };
        };

        if m_a == 0xff {
            println!("Exiting...");
            break;
        }

        // generate a random r_a
        let r_a: [u8; 32] = rand::random();
        // compute c_a = SHA256(m_a || r_a)
        let c_a = sha2::Sha256::new()
            .chain_update(&[m_a])
            .chain_update(&r_a)
            .finalize()
            .into();

        println!("Your move: {}", display_move(m_a));
        println!("Your random nonce: {}", hex::encode(r_a));

        let b_m = demo_client.commit(c_a).await?;
        if b_m > 2 {
            eprintln!("Invalid move received from Bob: {}", b_m);
            std::process::exit(1);
        }

        println!("Bob chose move: {}", display_move(b_m));

        println!("Press enter to reveal our move...");
        let mut dummy = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut dummy)
            .expect("Failed to read line");

        let winner = demo_client.reveal(m_a, r_a).await?;

        println!("Winner according to Bob: {}\n\n", parse_winner(winner));
    }
    let exit_code = demo_client.exit().await?;
    println!("V-App exited with code: {}", exit_code);
    Ok(())
}
