/*
A Cargo subcommand `cargo vnd package` to embed a manifest JSON into the built ELF as a custom section.

Usage:
  cargo vnd package [--app target/your/binary] [--cargo_toml_path your\app/manifest] [--output bundled_binary]

It can be called with no arguments if called from the folder containing the Cargo.toml file of th V-App.
*/

use anyhow::{Context, Result};
use cargo_generate::{GenerateArgs, TemplatePath};
use clap::{Parser, Subcommand};
use client_sdk::elf::{VAppElfFile, get_vapp_metadata};
use client_sdk::hash::Sha256;
use client_sdk::memory::MemorySegment;
use common::constants;
use common::manifest::Manifest;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MANIFEST_SECTION_SIZE: usize = 4096; // Size of the .manifest section in bytes

#[derive(Parser)]
#[command(name = "cargo-vnd", version, about = "Vanadium tools for cargo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Embed manifest into ELF
    Package {
        /// Path to the ELF binary (optional, deduced from manifest if not provided)
        #[arg(short, long, value_name = "ELF")]
        app: Option<PathBuf>,

        /// Path to the Cargo.toml manifest of the app (optional, defaults to ./Cargo.toml)
        #[arg(long, value_name = "CARGO_TOML")]
        cargo_toml_path: Option<PathBuf>,

        /// Output file path (optional, defaults to <crate-name>.vapp)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },
    /// Create a new V-App from a template
    New {
        /// Name of the new V-App. The template will have two crates: vnd-<name> and vnd-<name>-client
        #[arg(short, long, value_name = "NAME")]
        name: String,

        /// Path to a local template directory (optional, defaults to fetching from GitHub)
        #[arg(long, value_name = "PATH")]
        template_path: Option<PathBuf>,
    },
}

// The standard "objcopy" binary does not support RISCV targets.
// The riscv64 binary supports 32-bit targets as well.
const OBJCOPY_BINARY: &str = "riscv64-unknown-elf-objcopy";

fn main() -> Result<()> {
    // Skip the first argument ("vnd") when invoked as `cargo vnd`
    let cli = Cli::parse_from(std::env::args_os().skip(1));

    match cli.command {
        Commands::Package {
            app,
            cargo_toml_path,
            output,
        } => {
            let cargo_toml_path = cargo_toml_path
                .unwrap_or_else(|| std::env::current_dir().unwrap().join("Cargo.toml"));

            let (vapp_crate_name, vapp_version, vapp_metadata) =
                get_vapp_metadata(&cargo_toml_path)
                    .map_err(|e| anyhow::anyhow!(e))
                    .context("Failed to get V-App metadata from Cargo.toml")?;

            let elf_path = match app {
                Some(path) => path,
                // if the app path is not provided, default to release binary for the riscv32imc target
                None => cargo_toml_path
                    .parent()
                    .unwrap()
                    .join("target/riscv32imc-unknown-none-elf/release")
                    .join(vapp_crate_name),
            };
            // if the output path is not provided, default to adding the .vapp extension to the elf
            let output = output.unwrap_or_else(|| elf_path.with_extension("vapp"));
            create_vapp_package(&vapp_version, &vapp_metadata, &elf_path, &output)?;
        }
        Commands::New {
            name,
            template_path,
        } => {
            // Verify that the name is a valid crate name

            // Crate names must be at most 64 characters long
            const MAX_LENGTH: usize = 64 - "vnd-".len() - "-client".len();
            if name.len() > MAX_LENGTH {
                return Err(anyhow::anyhow!(
                    "Crate name too long. Maximum length is {} characters.",
                    MAX_LENGTH
                ));
            }

            // Check that the name contains only valid characters
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(anyhow::anyhow!(
                    "Invalid crate name. Only alphanumeric characters, hyphens, and underscores are allowed."
                ));
            }

            let vapp_crate_name = format!("vnd-{}", name);
            let client_crate_name = format!("vnd-{}-client", name);
            // binaries without hyphens (necessary for the lib and when importing in source code)
            let client_lib_binary_name = format!("vnd_{}_client", name);
            let cli_binary_name = format!("vnd_{}_cli", name);

            let template_path = if let Some(local_path) = template_path {
                // Use local template path
                TemplatePath {
                    path: Some(local_path.to_string_lossy().to_string()),
                    ..Default::default()
                }
            } else {
                // Use remote GitHub template
                TemplatePath {
                    auto_path: Some("https://github.com/LedgerHQ/vanadium.git".to_string()),
                    branch: Some("master".to_string()),
                    subfolder: Some("apps/template/generate".to_string()),
                    ..Default::default()
                }
            };

            let args = GenerateArgs {
                template_path,
                name: Some(name.clone()),
                define: vec![
                    format!("project-app-crate={}", vapp_crate_name),
                    format!("project-client-crate={}", client_crate_name),
                    format!("project-client-lib-binary={}", client_lib_binary_name),
                    format!("project-cli-binary={}", cli_binary_name),
                ],
                verbose: true,
                allow_commands: false,
                no_workspace: true,
                ..Default::default()
            };
            cargo_generate::generate(args)?;
        }
    }
    Ok(())
}

fn compute_merkle_roots(
    elf_file: &VAppElfFile,
    stack_start: u32,
    stack_size: u32,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let code_merkle_root: [u8; 32] =
        MemorySegment::new(elf_file.code_segment.start, &elf_file.code_segment.data)
            .get_content_root()
            .clone()
            .into();
    let data_merkle_root: [u8; 32] =
        MemorySegment::new(elf_file.data_segment.start, &elf_file.data_segment.data)
            .get_content_root()
            .clone()
            .into();
    let stack_merkle_root: [u8; 32] =
        MemorySegment::new(stack_start, &vec![0u8; stack_size as usize])
            .get_content_root()
            .clone()
            .into();

    Ok((code_merkle_root, data_merkle_root, stack_merkle_root))
}

fn create_vapp_package(
    vapp_version: &str,
    vapp_metadata: &client_sdk::cargo_toml::Value,
    input: &PathBuf,
    output: &PathBuf,
) -> Result<()> {
    // Ensure objcopy is available
    which::which(OBJCOPY_BINARY).context(format!(
        "`{}` not found in PATH. Please install it with `sudo apt install binutils-riscv64-unknown-elf` package (on Ubuntu/Debian) or find the equivalent package for your system.",
        OBJCOPY_BINARY
    ))?;

    let section_name = ".manifest";

    let app_name = vapp_metadata
        .get("name")
        .context("App name missing in metadata")?
        .as_str()
        .context("App name is not a string")?;

    let stack_size = vapp_metadata
        .get("stack_size")
        .context("Stack size missing in metadata")?
        .as_integer()
        .context("Stack size is not a number")?;

    if stack_size < constants::MIN_STACK_SIZE as i64
        || stack_size > constants::MAX_STACK_SIZE as i64
    {
        return Err(anyhow::anyhow!(
            "Stack size must be between {} and {} bytes",
            constants::MIN_STACK_SIZE,
            constants::MAX_STACK_SIZE
        ));
    }
    let stack_size = stack_size as u32;

    let n_storage_slots = match vapp_metadata.get("n_storage_slots") {
        None => 0,
        Some(value) => value
            .as_integer()
            .context("n_storage_slots is not a number")?,
    };

    if n_storage_slots < 0 || n_storage_slots > constants::MAX_STORAGE_SLOTS as i64 {
        return Err(anyhow::anyhow!(
            "n_storage_slots must be between 0 and {}",
            constants::MAX_STORAGE_SLOTS
        ));
    }
    let n_storage_slots = n_storage_slots as u32;

    // we might make it configurable in the future; for now, use a fixed value
    let stack_start = constants::DEFAULT_STACK_START;
    let stack_end = stack_start + stack_size;

    // Create a 4KB file filled with zeros for the empty .manifest section
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let pid = std::process::id();
    let zero_file =
        std::env::temp_dir().join(format!("manifest_zeroed_placeholder_{}_{}.bin", pid, now));
    std::fs::write(&zero_file, vec![0u8; MANIFEST_SECTION_SIZE])
        .context("Failed to write zero file")?;

    // Add the empty 4KB .manifest section to the input ELF, creating a temporary ELF file
    let temp_elf = std::env::temp_dir().join(format!("temp_elf_{}_{}.elf", pid, now));
    let status = Command::new(OBJCOPY_BINARY)
        .arg("--add-section")
        .arg(format!(".manifest={}", zero_file.display()))
        .arg(input)
        .arg(&temp_elf)
        .status()
        .context("Failed to run objcopy to add empty manifest section")?;
    if !status.success() {
        return Err(anyhow::anyhow!("objcopy command failed").into());
    }

    // Parse the temporary ELF file with the empty .manifest section
    let elf_file_with_manifest = VAppElfFile::new(&temp_elf)?;

    // Compute Merkle roots based on the ELF file with the empty section
    let (code_merkle_root, data_merkle_root, stack_merkle_root) =
        compute_merkle_roots(&elf_file_with_manifest, stack_start, stack_size)?;

    // Create the manifest with the computed Merkle roots
    let manifest = Manifest::new(
        0,
        app_name,
        vapp_version,
        elf_file_with_manifest.entrypoint,
        elf_file_with_manifest.code_segment.start,
        elf_file_with_manifest.code_segment.end,
        code_merkle_root,
        elf_file_with_manifest.data_segment.start,
        elf_file_with_manifest.data_segment.end,
        data_merkle_root,
        stack_start,
        stack_end,
        stack_merkle_root,
        n_storage_slots,
    )
    .map_err(|e| anyhow::anyhow!(e))
    .context("Failed to create VApp manifest")?;

    // Serialize the manifest to JSON
    let serialized_manifest = manifest.to_json()?;

    // Pad the serialized manifest to 4KB with zeros
    let mut padded_manifest = serialized_manifest.as_bytes().to_vec();
    if padded_manifest.len() > MANIFEST_SECTION_SIZE {
        return Err(anyhow::anyhow!("Serialized manifest exceeds maximum size").into());
    }
    padded_manifest.resize(MANIFEST_SECTION_SIZE, 0);

    // Write the padded manifest to a temporary file
    let padded_manifest_file =
        std::env::temp_dir().join(format!("padded_manifest_{}_{}.bin", pid, now));
    std::fs::write(&padded_manifest_file, &padded_manifest)
        .context("Failed to write padded manifest")?;

    // Update the .manifest section in the temporary ELF file with the padded manifest
    let status = Command::new(OBJCOPY_BINARY)
        .arg("--update-section")
        .arg(format!(
            "{}={}",
            section_name,
            padded_manifest_file.display()
        ))
        .arg(&temp_elf)
        .arg(output)
        .status()
        .context("Failed to run objcopy to update manifest section")?;
    if !status.success() {
        return Err(anyhow::anyhow!("objcopy command failed during manifest update").into());
    }

    println!("Saved packaged V-App in {}", output.display());

    let app_hash = manifest.get_vapp_hash::<Sha256, 32>();
    let app_hash_hex: String = app_hash.iter().map(|b| format!("{:02x}", b)).collect();

    println!("V-App info:");
    println!("  app name: {}", manifest.get_app_name());
    println!("  app version: {}", manifest.get_app_version());
    println!("  app hash: {}", app_hash_hex);
    println!(
        "  pages (code/data/stack): {}/{}/{}",
        manifest.n_code_pages(),
        manifest.n_data_pages(),
        manifest.n_stack_pages()
    );
    println!("  storage slots: {}", manifest.n_storage_slots);

    Ok(())
}
