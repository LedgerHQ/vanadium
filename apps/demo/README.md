This is a test V-App, with a few simple computations and functionalities to test various aspects of the Vanadium VM.

- [app](app) contains the Risc-V app, based on the V-app Sdk.
- [client](client) folder contains the client of the app, based on the V-app Client Sdk.

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
  cargo build --release --target=x86_64-unknown-linux-gnu
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

If you want to run the V-app on a real device, execute instead:

   ```sh
   cargo run -- --hid
   ```

If you want to run the V-app natively, after building it for the native target, use:

   ```sh
   cargo run -- --native
   ```



## Client commands

Once the client is running, these are the available commands:

- `reverse <hex_buffer>` - Reverses the given buffer.
- `sha256 <hex_buffer>` - Computes the sha256 hash of the given buffer.
- `b58enc <hex_buffer>` - Computes the base58 encoding of the given buffer (the output is in hex as well).
- `addnumbers <n>` - Computes the sum of the numbers between `1` and `n`.
- `nprimes <n>` - Counts the number of primes up to `n` using the Sieve of Eratosthenes.
- `panic <panic message>` - Cause the V-App to panic. Everything written after 'panic' is the panic message.
- An empty command will exit the V-App.
