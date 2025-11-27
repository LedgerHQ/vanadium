This is the Bitcoin app for Vanadium. It is composed of the following crates:

- [app](app) contains the V-app.
- [client](client) contains the client of the V-app.
- [common](common) contains the code shared between the V-App and the client.

The `client` is a library crate (see [lib.rs](client/src/lib.rs)), but it also has a test executable ([main.rs](client/src/main.rs)) to interact with the app from the command line.

## Build the V-App

### Risc-V

In order to build the app for the Risc-V target, enter the `app` folder and run:

   ```sh
   cargo build --release --target=riscv32imc-unknown-none-elf
   ```

### Native

In order to build the app for the native target, enter the `app` folder and run:

   ```sh
  cargo build --release
   ```

## Run the V-App

### Native target

Make sure you built the V-App for the native target.

On a terminal in the `app` folder, simply run:

   ```sh
   cargo run
   ```

On a different terminal in the `client` folder, run:

   ```sh
   cargo run -- --native
   ```

Note: you can customize the hostname and port of the app by setting the `VAPP_ADDRESS` environment variable.

### RISC-V target

Make sure you built the V-App for the RISC-V target.

Launch Vanadium on speculos. Then execute:

From the `client` folder

   ```sh
   cargo run
   ```

If you want to run the V-app on a real device, execute instead:

   ```sh
   cargo run -- --hid
   ```

## CLI usage

The executable client is a Command Line Interface to the features of the Bitcoin V-App, featuring autocomplete and command history.

Once the CLI interface is running, press TAB to see the existing command and their arguments.
