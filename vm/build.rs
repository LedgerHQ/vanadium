use std::env;

fn main() {
    println!("cargo:rerun-if-changed=script.ld");

    let target = env::var("TARGET").expect("TARGET not set");

    // optimize the HEAP_SIZE constant based on the target

    // minimum heap size that works for all targets
    const BASE_HEAP_SIZE: usize = 10 * 1024;

    let heap_size_extra_kb: usize = match target.as_str() {
        t if t.contains("nanosplus") => 16,
        t if t.contains("nanox") => 0,
        t if t.contains("flex") => 12,
        t if t.contains("stax") => 12,
        _ => {
            eprintln!("Unsupported target: {}", target);
            std::process::exit(1);
        }
    };
    let heap_size = BASE_HEAP_SIZE + heap_size_extra_kb * 1024;

    println!("cargo:rustc-env=HEAP_SIZE={}", heap_size);
    println!(
        "cargo:rustc-env=VANADIUM_N_EXTRA_CACHE_PAGES={}",
        heap_size_extra_kb * 3 // assuming 1 kb fits at least 3 pages
    );

    eprintln!(
        "\n\n\n\n@@@@@ Target: {}\n\n\n\n",
        std::env::var("TARGET").unwrap()
    );
}
