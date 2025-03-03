use clap::{CommandFactory, Parser, Subcommand};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::{Context, Editor, Helper};

use client::BitcoinClient;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;

use sdk::transport::{Transport, TransportHID, TransportTcp, TransportWrapper};
use sdk::vanadium_client::{NativeAppClient, VanadiumAppClient};

mod client;

use std::borrow::Cow;
use std::sync::Arc;

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
    RegisterAccount {
        #[clap(long)]
        name: Option<String>,
        #[clap(long)]
        descriptor_template: Option<String>,
        #[clap(long)]
        keys_info: Option<String>,
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
        #[clap(long, default_missing_value = "false", num_args = 0..=1)]
        is_change: bool,
        #[clap(long, default_missing_value = "0")]
        address_index: u32,
    },
    Exit,
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

    let mut rl = Editor::<CommandCompleter, rustyline::history::DefaultHistory>::new()?;
    rl.set_helper(Some(CommandCompleter));

    let _ = rl.load_history("history.txt");

    loop {
        match rl.readline("₿ ") {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                rl.add_history_entry(line.as_str())?;

                let clap_args = match prepare_prompt_for_clap(&line) {
                    Ok(args) => args,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        continue;
                    }
                };

                match Cli::try_parse_from(clap_args) {
                    Ok(cli) => match cli.command {
                        CliCommand::Exit => break,
                        CliCommand::GetFingerprint => {
                            let fpr = bitcoin_client.get_master_fingerprint().await?;
                            println!("{:08x}", fpr);
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
                            println!("(Not implemented)");
                        }
                        CliCommand::GetAddress {
                            display,
                            is_change,
                            address_index,
                            name,
                            descriptor_template,
                            keys_info,
                        } => {
                            println!(
                                "Executing get_address. Params: display={}, is_change={}, address_index={:?}, name={:?}, descriptor_template={:?}, keys_info={:?}",
                                display, is_change, address_index, name, descriptor_template, keys_info
                            );
                            let addr = bitcoin_client.get_address().await?;
                            println!("{}", addr);
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
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    rl.save_history("history.txt")?;

    bitcoin_client.exit().await?;

    Ok(())
}
