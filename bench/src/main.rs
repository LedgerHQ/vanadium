use client::BenchClient;
#[cfg(not(feature = "speculos"))]
use hidapi::HidApi;
#[cfg(not(feature = "speculos"))]
use sdk::transport::TransportHID;
#[cfg(feature = "speculos")]
use sdk::transport::TransportTcp;
use sdk::transport::TransportWrapper;

use sdk::transport_native_hid::TransportNativeHID;
use sdk::vanadium_client::VanadiumAppClient;
use std::env;
use std::sync::Arc;
use std::time::Instant;

mod client;

// Each testcase is a tuple of (name, repetitions)
// The name must be the same as the folder name in cases/ directory,
// and the crate must be named "vndbench-<name>".
const TEST_CASES: &[(&str, u64)] = &[
    ("nprimes", 1),    // counts the number of primes up to a given number
    ("base58enc", 10), // computes the base58 encoding of a 32-byte message using the bs58 crate
    ("sha256", 10),    // computes the SHA256 hash of a 32-byte message (without using ECALLs)
];

// Helper function to run a benchmark case and return (total_ms, avg_ms)
async fn run_bench_case(
    case: &str,
    repetitions: u64,
    vanadium_client: &mut VanadiumAppClient<Box<dyn std::error::Error + Send + Sync>>,
) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
    let crate_name = format!("vndbench-{}", case);
    let app_path_str = format!(
        "cases/{}/target/riscv32imc-unknown-none-elf/release/{}",
        case, crate_name
    );

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
        .start_vapp(&app_path_str, Box::new(print_writer))
        .await?;

    let mut client = BenchClient::new(vanadium_client);
    let start = Instant::now();
    let bench_result = client.run_and_exit(repetitions).await;
    let duration = start.elapsed();
    let total_ms = duration.as_secs_f64() * 1000.0;

    // Always stop the V-App (even if the benchmark errored).
    let _ = vanadium_client.stop_vapp().await;

    bench_result?;
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

    let args: Vec<String> = env::args().skip(1).collect();

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

    let testcases: Vec<_> = if args.is_empty() {
        TEST_CASES.iter().collect()
    } else {
        TEST_CASES
            .iter()
            .filter(|(case, _)| args.iter().any(|arg| case.contains(arg)))
            .collect()
    };

    if testcases.len() == 0 {
        println!("No test cases found matching the provided arguments.");
        return Ok(());
    } else if testcases.len() < TEST_CASES.len() {
        print!("Selected test cases: ");
        for (i, (case, _)) in testcases.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", case);
        }
        println!();
    }

    // Run the _baseline app first, to measure baseline time
    let baseline_total_ms = run_bench_case("_baseline", 1, &mut vanadium_client).await?;
    // Print baseline time
    println!("Baseline time: {:.3} ms", baseline_total_ms);

    // Print summary table header before running benchmarks
    println!("\n================ Benchmark Results ================");
    println!(
        "{:<15} {:>10} {:>18} {:>18}",
        "Test", "Runs", "Total (ms)", "Avg/Run (ms)",
    );
    println!("{:-<65}", "");

    for (case, repetitions) in testcases {
        println!(
            "cases/{}/target/riscv32imc-unknown-none-elf/release/vndbench-{}",
            case, case
        );
        let total_ms = run_bench_case(case, *repetitions, &mut vanadium_client).await?;
        // Subtract baseline time
        let adj_total_ms = (total_ms - baseline_total_ms).max(0.0);
        let adj_avg_ms = adj_total_ms / *repetitions as f64;
        println!(
            "{:<15} {:>10} {:>18.3} {:>18.3}",
            case, repetitions, adj_total_ms, adj_avg_ms
        );
    }
    println!("{:=<65}", "");
    Ok(())
}
