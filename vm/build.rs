use std::{env, fs::write, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=script.ld");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let raw_heap_size = env::var("HEAP_SIZE").unwrap();

    // smallest heap size, tailored for Nano X
    let base_heap_size = 14336usize;
    // heap size for the current target
    let heap_size = parse_heap_size(&raw_heap_size, &target_os);

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("heap_size.rs");
    write(
        &out,
        format!(
            "pub const BASE_HEAP_SIZE: usize = {base_heap_size};\n\
             pub const HEAP_SIZE: usize = {heap_size};\n"
        ),
    )
    .unwrap();
    println!("cargo:rerun-if-env-changed=HEAP_SIZE");
}

fn parse_heap_size(raw: &str, target_os: &str) -> usize {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        panic!("HEAP_SIZE is not defined");
    }

    if let Ok(v) = trimmed.parse::<usize>() {
        return v;
    }

    // Parse list of comma-separated target:value pairs
    for entry in trimmed.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some((k, v_str)) = entry.split_once(':') {
            if k.trim() == target_os {
                if let Ok(v) = v_str.trim().parse::<usize>() {
                    return v;
                }
            }
        }
    }
    panic!("HEAP_SIZE is not defined for the current target_os");
}
