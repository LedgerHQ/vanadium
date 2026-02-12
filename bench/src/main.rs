use clap::Parser;
use client::BenchClient;
#[cfg(not(feature = "speculos"))]
use hidapi::HidApi;
#[cfg(not(feature = "speculos"))]
use sdk::transport::TransportHID;
#[cfg(feature = "speculos")]
use sdk::transport::TransportTcp;
use sdk::transport::TransportWrapper;
#[cfg(feature = "metrics")]
use std::fs::File;

use sdk::transport_native_hid::TransportNativeHID;
use sdk::vanadium_client::VanadiumAppClient;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod client;

const DEFAULT_REPETITIONS: u64 = 10;

#[derive(Parser, Debug)]
#[command(name = "vanadium-benchmarks")]
#[command(about = "Run Vanadium benchmarks", long_about = None)]
struct Args {
    /// Path to the directory containing benchmark test cases
    #[arg(short, long, default_value = "cases")]
    path: PathBuf,

    /// List available test cases without running them
    #[arg(long)]
    list: bool,

    /// Filter test cases by name (can specify multiple)
    filters: Vec<String>,
}

#[derive(Debug, Clone)]
struct BenchCase {
    case_name: String,
    crate_name: String,
    repetitions: u64,
}

impl BenchCase {
    fn app_path(&self) -> String {
        format!(
            "cases/{}/target/riscv32imc-unknown-none-elf/release/{}",
            self.case_name, self.crate_name
        )
    }
}

fn discover_bench_cases(
    cases_dir: &Path,
) -> Result<Vec<BenchCase>, Box<dyn std::error::Error + Send + Sync>> {
    let mut cases = Vec::new();

    for entry in fs::read_dir(cases_dir)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        if !entry_type.is_dir() {
            continue;
        }

        let case_name = entry.file_name().to_string_lossy().to_string();
        if case_name.starts_with('.') {
            continue;
        }

        let manifest_path = entry.path().join("Cargo.toml");
        if !manifest_path.is_file() {
            continue;
        }

        let manifest_contents = fs::read_to_string(&manifest_path)?;
        let manifest = manifest_contents.parse::<toml::Value>()?;

        let package = manifest
            .get("package")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                format!(
                    "Missing [package] table in manifest: {}",
                    manifest_path.display()
                )
            })?;

        let crate_name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "Missing package.name in manifest: {}",
                    manifest_path.display()
                )
            })?
            .to_string();

        let repetitions = package
            .get("metadata")
            .and_then(|v| v.get("benchmark"))
            .and_then(|v| v.get("repetitions"))
            .and_then(toml::Value::as_integer)
            .map(u64::try_from)
            .transpose()?
            .unwrap_or(DEFAULT_REPETITIONS);
        if repetitions == 0 {
            return Err(format!(
                "benchmark.repetitions must be > 0 in {}",
                manifest_path.display()
            )
            .into());
        }

        let case = BenchCase {
            case_name,
            crate_name,
            repetitions,
        };

        cases.push(case);
    }

    cases.sort_unstable_by(|a, b| a.case_name.cmp(&b.case_name));
    Ok(cases)
}

#[cfg(feature = "metrics")]
fn save_metrics(
    case: &BenchCase,
    metrics: &common::metrics::VAppMetrics,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filename = format!("{}.metrics", case.case_name);
    let mut file = File::create(&filename)?;

    writeln!(file, "V-App Name: {}", metrics.get_vapp_name())?;
    writeln!(file, "V-App Hash: {}", hex::encode(metrics.vapp_hash))?;
    writeln!(file, "Instruction Count: {}", metrics.instruction_count)?;
    writeln!(file, "Page Loads: {}", metrics.page_loads)?;
    writeln!(file, "Page Commits: {}", metrics.page_commits)?;

    Ok(())
}

// Helper function to run a benchmark case and return total time in ms
async fn run_bench_case(
    case: &BenchCase,
    repetitions: u64,
    vanadium_client: &mut VanadiumAppClient<Box<dyn std::error::Error + Send + Sync>>,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    // Best-effort cleanup in case a prior run didn't stop cleanly.
    let _ = vanadium_client.stop_vapp().await;

    #[cfg(feature = "debug")]
    let print_writer = Box::new(sdk::linewriter::FileLineWriter::new(
        "print.log",
        true,
        true,
    ));
    #[cfg(not(feature = "debug"))]
    let print_writer = Box::new(std::io::sink());

    vanadium_client
        .start_vapp(&case.app_path(), Box::new(print_writer))
        .await?;

    let mut client = BenchClient::new(vanadium_client);
    let start = Instant::now();
    let bench_result = client.run_and_exit(repetitions).await;
    let duration = start.elapsed();
    let total_ms = duration.as_secs_f64() * 1000.0;

    // Always stop the V-App (even if the benchmark errored).
    let _ = vanadium_client.stop_vapp().await;

    bench_result?;

    // Save metrics if the feature is enabled
    #[cfg(feature = "metrics")]
    {
        // do not save metrics on the baseline run with 0 repetitions
        if repetitions > 0 {
            match vanadium_client.get_metrics().await {
                Ok(metrics) => {
                    if let Err(e) = save_metrics(case, &metrics) {
                        eprintln!(
                            "Warning: Failed to save metrics for {}: {}",
                            case.case_name, e
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to get metrics for {}: {}",
                        case.case_name, e
                    );
                }
            }
        }
    }

    Ok(total_ms)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "debug")]
    {
        let log_file = std::fs::File::create("debug.log")?;
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
    }

    let args = Args::parse();

    let all_cases = discover_bench_cases(&args.path)?;
    let testcases: Vec<_> = if args.filters.is_empty() {
        all_cases.iter().collect()
    } else {
        all_cases
            .iter()
            .filter(|case| {
                args.filters
                    .iter()
                    .any(|filter| case.case_name.contains(filter.as_str()))
            })
            .collect()
    };

    if args.list {
        for case in &testcases {
            println!("{} (runs={})", case.case_name, case.repetitions);
        }
        return Ok(());
    }

    #[cfg(not(feature = "speculos"))]
    let transport = {
        let transport_raw = Arc::new(TransportHID::new(
            TransportNativeHID::new(&HidApi::new().expect("Unable to get connect to the device"))
                .unwrap(),
        ));

        Arc::new(TransportWrapper::new(transport_raw.clone()))
    };

    #[cfg(feature = "speculos")]
    let transport = {
        let transport_raw = Arc::new(
            TransportTcp::new_default()
                .await
                .expect("Unable to connect to Speculos"),
        );

        Arc::new(TransportWrapper::new(transport_raw.clone()))
    };

    // Create the Vanadium client once (without running any V-App).
    let mut vanadium_client = match VanadiumAppClient::new(transport.clone()).await {
        Ok(c) => c,
        Err(_) => {
            println!("Please make sure the device is unlocked and the Vanadium app is open.");
            return Ok(());
        }
    };

    // Print the name/model of the connected device(s) before running benchmarks.
    let app_info = vanadium_client.get_app_info().await?;
    println!("Device: {}", app_info.device_model);

    if testcases.len() == 0 {
        println!("No test cases found matching the provided arguments.");
        return Ok(());
    } else if testcases.len() < all_cases.len() {
        print!("Selected test cases: ");
        for (i, case) in testcases.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", case.case_name);
        }
        println!();
    }

    // Print summary table header before running benchmarks
    println!("\n================ Benchmark Results ================");
    println!(
        "{:<15} {:>10} {:>18} {:>18} {:>18}",
        "Test", "Runs", "Init (ms)", "Total (ms)", "Avg/Run (ms)",
    );
    println!("{:-<83}", "");

    for case in testcases {
        print!("{:<15} {:>10} ", case.case_name, case.repetitions);
        std::io::stdout().flush().unwrap(); // show test name and repetitions before running it

        // Run with 0 repetitions to measure initialization time
        let init_ms = run_bench_case(case, 0, &mut vanadium_client).await?;

        // Run with actual repetitions
        let total_with_init_ms =
            run_bench_case(case, case.repetitions, &mut vanadium_client).await?;

        // Subtract initialization time from total
        let total_ms = (total_with_init_ms - init_ms).max(0.0);
        let avg_ms = total_ms / case.repetitions as f64;

        println!("{:>18.3} {:>18.3} {:>18.3}", init_ms, total_ms, avg_ms);
    }
    println!("{:=<83}", "");
    Ok(())
}
