use base64::Engine as _;
use bitcoin::psbt::Psbt;

use clap::{CommandFactory, Parser, Subcommand};
use common::account::ProofOfRegistration;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Editor, Helper};

use client::BitcoinClient;

mod client;

use sdk::vanadium_client::client_utils::{create_default_client, ClientType};

use std::borrow::Cow;

use crate::client::BitcoinClientError;

#[derive(Parser, Debug)]
#[command(name = "vnd-bitcoin-cli")]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
#[clap(rename_all = "snake_case")]
enum CliCommand {
    GetFingerprint,
    GetPubkey {
        #[clap(long)]
        path: String,
        #[clap(long, default_missing_value = "true", num_args = 0..=1)]
        display: bool,
    },
    RegisterAccount {
        #[clap(long)]
        name: String,
        #[clap(long)]
        descriptor_template: String,
        #[clap(long)]
        keys_info: String,
    },
    GetAddress {
        #[clap(long, default_missing_value = "true", num_args = 0..=1)]
        display: bool,
        #[clap(long)]
        name: Option<String>,
        #[clap(long)]
        descriptor_template: String,
        #[clap(long)]
        keys_info: String,
        #[clap(long)]
        por: Option<String>,
        #[clap(long, default_missing_value = "false", num_args = 0..=1)]
        is_change: bool,
        #[clap(long, default_missing_value = "0")]
        address_index: u32,
    },
    SignPsbt {
        #[clap(long)]
        psbt: String,
    },
}

// Command completer
struct CommandCompleter;

impl CommandCompleter {
    fn get_current_word<'a>(&self, line: &'a str, pos: usize) -> (usize, &'a str) {
        let before = &line[..pos];
        // Find the last space before the cursor; if none, start at 0
        let start = before.rfind(' ').map_or(0, |i| i + 1);
        let word = &line[start..pos];
        (start, word)
    }
}

fn make_pair(s: &str) -> Pair {
    Pair {
        display: s.to_string(),
        replacement: s.to_string(),
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = line[..pos].trim_start();

        // Case 1: Empty input, suggest all subcommands
        if prefix.is_empty() || !prefix.contains(' ') {
            let suggestions = Cli::command()
                .get_subcommands()
                .filter(|cmd| cmd.get_name().starts_with(prefix))
                .map(|cmd| make_pair(cmd.get_name()))
                .collect();
            return Ok((0, suggestions));
        }

        // Case 3: Subcommand present; suggest possible arguments to complete the command
        let subcmd_name = prefix.split_whitespace().next().unwrap();
        if let Some(subcmd) = Cli::command().find_subcommand(subcmd_name) {
            let (start, _) = self.get_current_word(line, pos);

            // Collect arguments already present in the line before the cursor
            let Ok(present_args) = shellwords::split(&line[..start].trim_end()) else {
                return Ok((0, vec![])); // no suggestions if we can't parse the line
            };

            // replace `argument=some_value` with just `argument` for each of present_args
            let present_args: Vec<String> = present_args
                .into_iter()
                .map(|arg| arg.split('=').next().unwrap().to_string())
                .collect();

            // Get all argument continuations
            let suggestions = subcmd
                .get_arguments()
                .filter_map(|arg| arg.get_long().map(|l| l.to_string()))
                .filter(|arg| !present_args.contains(arg))
                .map(|arg| Pair {
                    display: arg.clone(),
                    replacement: arg,
                })
                .collect();
            return Ok((start, suggestions));
        }

        // Default case: no suggestions
        Ok((0, vec![]))
    }
}

impl Validator for CommandCompleter {
    fn validate(
        &self,
        _ctx: &mut ValidationContext<'_>,
    ) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None))
    }
}

impl Highlighter for CommandCompleter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Borrowed(line)
    }

    fn highlight_char(&self, _line: &str, _pos: usize, _cmd_kind: CmdKind) -> bool {
        false
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Helper for CommandCompleter {}

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

// a bit of a hack: we convert the prompt in a format that clap can parse
// (adding a dummy command, and replacing each 'argument' with '--argument')
fn prepare_prompt_for_clap(line: &str) -> Result<Vec<String>, String> {
    let args = shellwords::split(line).map_err(|e| format!("Failed to parse input: {}", e))?;
    if args.is_empty() {
        return Err("Empty input".to_string());
    }

    // dummy command, and first command unchanged
    let mut clap_args = vec!["dummy".to_string(), args[0].clone()];

    // prepend `--` to each subsequent argument
    for arg in &args[1..] {
        clap_args.push(format!("--{}", arg));
    }
    Ok(clap_args)
}

// parse the keys_info arg in the format "key_info1, key_info2, ..."
fn parse_keys_info(keys_info: &str) -> Result<Vec<common::bip388::KeyInformation>, &'static str> {
    let keys_info = keys_info
        .split(',')
        .map(|ki| ki.trim()) // tolerate extra spaces
        .map(|ki| common::bip388::KeyInformation::try_from(ki))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(keys_info)
}

fn parse_wallet_policy(
    descriptor_template: &str,
    keys_info: &str,
) -> Result<common::message::WalletPolicy, &'static str> {
    let keys_info = parse_keys_info(keys_info)?;
    let wallet_policy_msg = common::message::WalletPolicy {
        template: descriptor_template.to_string(),
        keys_info: keys_info
            .iter()
            .map(|ki| common::message::PubkeyInfo {
                pubkey: ki.pubkey.encode().to_vec(),
                origin: ki
                    .origin_info
                    .as_ref()
                    .map(|origin_info| common::message::KeyOrigin {
                        fingerprint: origin_info.fingerprint,
                        path: common::message::Bip32Path(
                            origin_info
                                .derivation_path
                                .iter()
                                .map(|step| u32::from(*step))
                                .collect(),
                        ),
                    }),
            })
            .collect(),
    };
    Ok(wallet_policy_msg)
}

async fn handle_cli_command(
    bitcoin_client: &mut BitcoinClient,
    cli: &Cli,
) -> Result<(), BitcoinClientError> {
    match &cli.command {
        CliCommand::GetFingerprint => {
            let fpr = bitcoin_client.get_master_fingerprint().await?;
            println!("{:08x}", fpr);
        }
        CliCommand::GetPubkey { path, display } => {
            let xpub = bitcoin_client.get_extended_pubkey(&path, *display).await?;

            match bitcoin::bip32::Xpub::decode(&xpub) {
                Ok(xpub) => println!("{}", xpub),
                Err(_) => println!("Invalid xpub returned"),
            }
        }
        CliCommand::RegisterAccount {
            name,
            descriptor_template,
            keys_info,
        } => {
            println!(
                "Executing register_account for {:?} account: {:?} {:?}",
                name, descriptor_template, keys_info
            );

            let wallet_policy_msg = parse_wallet_policy(descriptor_template, keys_info)?;
            let account = common::message::Account::WalletPolicy(wallet_policy_msg);
            let (account_id, hmac) = bitcoin_client.register_account(name, &account).await?;
            println!(
                "Account {} registered.\nAccount ID: {}\nHMAC: {}",
                name,
                hex::encode(account_id),
                hex::encode(hmac.dangerous_as_bytes())
            );
        }
        CliCommand::GetAddress {
            display,
            is_change,
            address_index,
            name,
            descriptor_template,
            por,
            keys_info,
        } => {
            let wallet_policy_msg = parse_wallet_policy(descriptor_template, keys_info)?;
            let wallet_policy_coords = common::message::WalletPolicyCoordinates {
                is_change: *is_change,
                address_index: *address_index,
            };
            // convert por from hex to bytes if provided
            let proof_of_registration = por
                .as_ref()
                .map(|s| -> Result<ProofOfRegistration, &'static str> {
                    let bytes =
                        hex::decode(s).map_err(|_| "Failed to decode proof of registration")?;

                    let array: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| "Proof of registration must be 32 bytes long")?;

                    Ok(ProofOfRegistration::from_bytes(array))
                })
                .transpose()?; // Result<Option<ProofOfRegistration>, _>

            let addr = bitcoin_client
                .get_address(
                    &common::message::Account::WalletPolicy(wallet_policy_msg),
                    name.as_deref().unwrap_or(""),
                    &common::message::AccountCoordinates::WalletPolicy(wallet_policy_coords),
                    proof_of_registration.as_ref(),
                    *display,
                )
                .await?;
            println!("{}", addr);
        }
        CliCommand::SignPsbt { psbt } => {
            let mut psbt = base64::engine::general_purpose::STANDARD
                .decode(&psbt)
                .map_err(|_| "Failed to decode PSBT")?;

            // At this time, rust-bitcoin only supports PSBT version 0. Therefore, if parsing
            // succeeds, we assume it's a valid PSBTv0, and we convert it to version 2.
            // To be rewritten once rust-bitcoin supports PSBTv2.
            if let Ok(parsed_psbt) = Psbt::deserialize(&psbt) {
                assert!(parsed_psbt.version == 0);
                psbt = common::psbt::psbt_v0_to_v2(&psbt)
                    .map_err(|_| "Failed to convert PSBTv0 to PSBTv2")?;
            }

            let partial_sigs = bitcoin_client.sign_psbt(&psbt).await?;

            println!("{} signatures returned", partial_sigs.len());
            for part_sig in &partial_sigs {
                println!("Input index: {}", part_sig.input_index);
                println!("Public key: {}", hex::encode(&part_sig.pubkey));
                println!("Signature: {}", hex::encode(&part_sig.signature));
                if let Some(leaf_hash) = &part_sig.leaf_hash {
                    println!("Leaf hash: {}", hex::encode(leaf_hash));
                }
            }
        }
    }
    Ok(())
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
    let mut bitcoin_client =
        BitcoinClient::new(create_default_client("vnd-bitcoin", client_type).await?);

    let mut rl = Editor::<CommandCompleter, rustyline::history::DefaultHistory>::new()?;
    rl.set_helper(Some(CommandCompleter));

    let _ = rl.load_history("history.txt");

    let mut with_unrecoverable_error = false;
    loop {
        match rl.readline("₿ ") {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }

                if line.trim() == "exit" {
                    println!("Exiting");
                    break;
                }

                rl.add_history_entry(line.as_str())?;

                let clap_args = match prepare_prompt_for_clap(&line) {
                    Ok(args) => args,
                    Err(e) => {
                        println!("Error: {}", e);
                        continue;
                    }
                };

                match Cli::try_parse_from(clap_args) {
                    Ok(cli) => match handle_cli_command(&mut bitcoin_client, &cli).await {
                        Ok(_) => {}
                        Err(BitcoinClientError::AppError(e)) => {
                            // The V-App returned an error, but it's still running fine
                            println!("The V-App returned an error: {}", e);
                        }
                        Err(e) => {
                            // Other errors can't be recovered from
                            println!("Fatal error: {}", e);
                            with_unrecoverable_error = true;
                            break;
                        }
                    },
                    Err(e) => println!("Invalid command: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => println!("Interrupted"),
            Err(ReadlineError::Eof) => {
                println!("Exiting");
                break;
            }
            Err(err) => {
                println!("Error reading the line: {:?}", err);
                continue;
            }
        }
    }

    rl.save_history("history.txt")?;

    if !with_unrecoverable_error {
        // close the client gracefully
        let exit_status = bitcoin_client.exit().await?;
        if exit_status != 0 {
            println!("V-App exited with status: {}", exit_status);
        }
    }

    Ok(())
}
