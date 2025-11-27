This is a Boilerplate V-App.

- [app](app) contains the Risc-V app for Vanadium.
- [client](client) folder contains the client of the app, and a simple CLI interface.

The `client` is a library crate (see [lib.rs](client/src/lib.rs)), but it also has a test executable ([main.rs](client/src/main.rs)) to interact with the app from the command line.

## Build the V-App

If you installed [just](https://github.com/casey/just), simply running `just` from the `app` folder will build both the
Risc-V and the native binaries.

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

### RISC-V

Make sure you built the V-App for the RISC-V target.

Launch Vanadium on speculos. Then execute:

From the `client` folder

   ```sh
   cargo run
   ```

If you want to run the V-app on a real device, launch the Vanadium app on the device, then execute instead:

   ```sh
   cargo run -- --hid
   ```
