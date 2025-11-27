This is a test V-App to test functionalities of the app-sdk in a real V-App.

- [app](app) contains the Risc-V app, based on the V-app Sdk.
- [client](client) folder contains the client of the app, based on the V-app Client Sdk.
- [common](common) a crate with code shared by both the app and the client.

The [client/tests](client/tests) folder contains integration tests to run with Speculos.

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

## Tests with speculos

In order to run the integration tests, enter the `client` folder and run:

   ```sh
  cargo test --features speculos-tests
   ```
