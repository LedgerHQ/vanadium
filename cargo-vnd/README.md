# cargo-vnd

This crate contains `cargo` commands for developers of Vanadium V-Apps.

## Installation

This program requires `riscv64-unknown-elf-objcopy`. On Ubuntu, this can be installed with:

```
sudo apt install binutils-riscv64-unknown-elf
```

Install `cargo-vnd` with:

```
cargo install --git https://github.com/LedgerHQ/vanadium cargo-vnd
```

or download it manually and install with:

```
cargo install --path .
```

from the `cargo-vnd` folder of the vanadium repository.

## Usage

General usage is displayed when invoking `cargo vnd`, or `cargo vnd <subcommand> -h` for details about specific subcommands.

At this time, there is a single subcommand:

- `package`: Prepares a packaged V-App by embedding its manifest in the binary. After building the `release` version for the RISC-V target, call the `cargo vnd package` command with no arguments from the V-App's crate folder. This will produce a binary with the added extension `.vapp`, with the app's manifest embedded in it. The paths of input and output files can be customized with command line arguments if needed.

**Example:**

```
cargo build --release --target riscv32imc-unknown-none-elf
cargo vnd package
```

This will create a file like `target/riscv32imc-unknown-none-elf/release/<appname>.vapp`.