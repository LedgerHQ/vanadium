# DISCLAIMER

:warning: | THIS IS AN EXPERIMENTAL PROJECT. IT IS INSECURE AT THIS STAGE<br/>Please don't start depending on it, and do not use it in production. Large parts of this project are subject to change. | :warning:
:---: | :--- | :---

---

# Vanadium

Vanadium is a Risc-V Virtual Machine that runs in an embedded Secure Element.

<img align="right" src="docs/assets/vanadium_logo.png" alt="Vanadium Logo" style="width: 50%; min-width: 200px; max-width: 280px"/>

By outsourcing encrypted, authenticated pages to an untrusted client, it allows you to run applications (V-Apps) in the secure element without worrying about the limitations of the embedded platform.

*   **No memory constraints:** Only the code and data actually used at runtime is sent to the device. Page swapping happens transparently.
*   **Native Development:** Write and test code natively on your machine before deploying to the embedded device.
*   **Secure:** Execution happens in the Secure Element. Page authentication and encryption prevents the host from tampering. 

# Developer Quick Start

## Prerequisites

Before you begin, ensure you have the following installed:

1.  **Rust & Risc-V Target:**
    ```bash
    rustup target add riscv32imc-unknown-none-elf
    ```

2.  **just** (Command runner):
    *   Ubuntu/Debian: `sudo apt install just`
    *   macOS: `brew install just`
    *   Other: See [just installation guide](https://github.com/casey/just).
    
    We recommend to also install its autocomplete for the shell you are using.

3.  **System Tools:**
    *   Ubuntu/Debian: `sudo apt install binutils-riscv64-unknown-elf` (Required for `riscv64-unknown-elf-objcopy`, used by the `cargo vnd package` command)
if not using Ubuntu/Debian, this utility might be in a different package.

4.  **cargo-vnd** (Vanadium build tool):
    ```bash
    cargo install --git https://github.com/LedgerHQ/vanadium cargo-vnd
    ```

## Setup

Clone this repository to get access to the build scripts and emulator tools:

```bash
git clone https://github.com/LedgerHQ/vanadium.git
cd vanadium
```

## Hello World

Create a new project named `hello`. You can do this in the root of the repo or a separate workspace.

```bash
cargo vnd new --name hello
```

This creates:
*   `hello/app`: The V-App (runs on device)
*   `hello/client`: The client and CLI interface (runs on computer)

## Building and Running

### 1. Build the V-App
Go to the app directory and build:

```bash
cd hello/app
just build
```

This builds the app for both the native and the Risc-V targets.

You can also run its tests:

```bash
cargo test
```

### 2. Run Natively
You can test your app logic without any hardware or emulator by running both the app and the client on your computer, in two different terminals. The two programs will communicate over a socket.


**Terminal 1 (The App):**
```bash
cd hello/app
cargo run
```

You can interact with the app (when needed) via the terminal.

**Terminal 2 (The Client):**
```bash
cd hello/client
cargo run -- --native
```

### 3. Run on Speculos Emulator
This section requires the installation of the [speculos](https://github.com/LedgerHQ/speculos) emulator, for example with:

```bash
pipx install speculos
```

To run on the device emulator, you first need the **Vanadium VM** binary.

1.  **Download the precompiled VM binary:**
    ```bash
    cd vm
    bash download_vanadium.sh
    ```
    Alternatively, find the instructions to compile the app in the [vm](vm) folder.

2.  **Launch the Emulator (in the `vm` folder):**
    ```bash
    just run-nanosplus  # Options: run-nanox, run-flex, run-stax, run-apex_p
    ```

3.  **Run your Client (in `hello/client`):**
    ```bash
    cargo run
    ```

### 4. Run on Ledger Device

On all devices except Nano X, you can sideload the Vanadium app.

One option is to use the [Ledger VSCode Extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).

Alternatively, install the following dependencies:

```bash
sudo apt install libudev-dev libusb-1.0-0-dev python3-venv
```

Then, connect and unlock the device, and run:

```bash
cd vm
# Download binaries if not already present
if [ ! -d "target" ]; then bash download_vanadium.sh; fi
bash load_vanadium.sh    
```

Once Vanadium is installed:

1.  Connect your device and open the Vanadium App.
2.  Run the client:
    ```bash
    cd hello/client
    cargo run -- --hid
    ```

# Repository Structure

This repository is organized in a monorepo structure.

* [docs](docs) - Architecture and technical documentation
* [VM](vm) <small>[<tt>arm</tt>], no-std</small> - The Vanadium Ledger app. It contains the actual Virtual Machine.
* [app-sdk](app-sdk) <small>[<tt>riscv</tt>], no_std</small> - Vanadium V-App SDK. It is used by V-Apps to access all the system services.
* [client-sdk](client-sdk) <small>[<tt>native</tt>]</small> - Vanadium V-App client SDK. V-App Clients use it as a base for their own client crates.
* [common](common) <small>[<tt>arm|riscv|native</tt>], no_std</small> - Any code that is shared among two or more of the above crates.
* [apps](apps) - Complete V-Apps, and their clients.
  * [template](apps/template) - A minimal boilerplate app used as a template by `cargo vnd new`.
  * [rps](apps/rps) - Play Rock-Paper-Scissors against your hardware signer.
  * [bitcoin](apps/bitcoin) - A work-in-progess app for signing bitcoin transactions.
  * [test](apps/test) - Simple V-App to test the Vanadium VM, implementing various computational tasks.
  * [sadik](apps/sadik) - A V-App specifically designed to test the various functionality of the Vanadium V-App SDK, and particularly the ECALLs.
* [libs](libs) - General purpose libraries that can be used by V-Apps.
  * [bitcoin](libs/bitcoin) - A custom clone of the [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) library.
* [cargo-vnd](cargo-vnd) - A tool to create and package V-Apps.

## Vanadium Developers

If you want to contribute to Vanadium itself (the VM or SDKs), open the `vanadium.code-workspace` in VSCode. This workspace is configured for multi-crate development.

Find more information on how to install the necessary tools to develop the Vanadium VM Ledger app in the [vm](vm) folder.

## License

This project is licensed under the [Apache Licence v2.0](LICENSE).

Individual crates inside this repository might be release under a different license - that will be specified in the corresponding `LICENSE` file.
