use client::BenchClient;
use hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use sdk::transport::{TransportHID, TransportWrapper};
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
    transport: Arc<TransportWrapper>,
) -> Result<f64, Box<dyn std::error::Error>> {
    let crate_name = format!("vndbench-{}", case);
    let app_path_str = format!(
        "cases/{}/target/riscv32imc-unknown-none-elf/release/{}",
        case, crate_name
    );
    let (client_raw, _) = VanadiumAppClient::new(&app_path_str, transport, None)
        .await
        .map_err(|_| "Failed to create client")?;
    let mut client = BenchClient::new(Box::new(client_raw));
    let start = Instant::now();
    client.run_and_exit(repetitions).await?;
    let duration = start.elapsed();
    let total_ms = duration.as_secs_f64() * 1000.0;
    Ok(total_ms)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let transport_raw = Arc::new(TransportHID::new(
        TransportNativeHID::new(&HidApi::new().expect("Unable to get connect to the device"))
            .unwrap(),
    ));
    let transport = Arc::new(TransportWrapper::new(transport_raw.clone()));

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
    let baseline_total_ms = run_bench_case("_baseline", 1, transport.clone()).await?;
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
        let total_ms = run_bench_case(case, *repetitions, transport.clone()).await?;
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
