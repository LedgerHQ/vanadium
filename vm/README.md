This is the Vanadium Risc-V VM app. For now, it's just boilerplate.

# Ledger Rust Boilerplate Application

![Rule enforcer](https://github.com/LedgerHQ/app-boilerplate-rust/actions/workflows/guidelines_enforcer.yml/badge.svg) ![Build and tests](https://github.com/LedgerHQ/app-boilerplate-rust/actions/workflows/build_and_functional_tests.yml/badge.svg)

This is a boilerplate application written in Rust which can be forked to start a new project for the Ledger Nano X/SP, Stax and Flex devices.

:warning: Nano S is not supported

* Implements standard features (display address, transaction signature...),
* Has functional tests using [Ragger](https://github.com/LedgerHQ/ragger),
* Has CI workflows mandatory for app deployment in the Ledger store.

### Links

* 📚 [Developer's documentation](https://developers.ledger.com/)<br/>
* 🗣️ [Ledger's Discord server](https://discord.gg/Ledger)

## Quick start guide

### With VS Code

You can quickly setup a development environment on any platform (macOS, Linux or Windows) to build and test your application with [Ledger's VS Code extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).

By using Ledger's own developer tools [Docker image](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools), the extension allows you to **build** your apps with the latest SDK, **test** them on **Speculos** and **load** them on any supported device.

* Install and run [Docker](https://www.docker.com/products/docker-desktop/).
* Make sure you have an X11 server running :
  * On Ubuntu Linux, it should be running by default.
  * On macOS, install and launch [XQuartz](https://www.xquartz.org/) (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  * On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/) (make sure to configure it to disable access control).
* Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
* Open a terminal and clone `app-boilerplate-rust` with `git clone git@github.com:LedgerHQ/app-boilerplate-rust.git`.
* Open the `app-boilerplate-rust` folder with VSCode.
* Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b` (`command + shift + b` on a Mac) to conveniently execute actions :
  * **Build** the app for the device model of your choice with `Build`.
  * **Test** your binary on the [Speculos emulator](https://github.com/LedgerHQ/speculos) with `Run with emulator`.
  * You can also **run functional tests**, load the app on a physical device, and more.

ℹ️ The terminal tab of VSCode will show you what commands the extension runs behind the scene.

## Compilation and load

If you do not wish to use the [VS Code extension](#with-vs-code), you can follow the following steps to setup a development environment on a host running a Debian based Linux distribution (such as Ubuntu).

### Prerequisites

* Install the [Rust language](https://www.rust-lang.org/)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

* Install Ledger Rust building tools dependencies

```bash
# Clang compiler, GCC ARM cross-compiling toolchain 
apt install clang gcc-arm-none-eabi gcc-multilib
# Rust nightly toolchain used to compile ledger devices binaries
rustup install nightly-2023-11-10
# Setup the custom nightly Rust toolchain as default
rustup default nightly-2023-11-10
# Install required component of the nightly toolchain
rustup component add rust-src --toolchain nightly-2023-11-10
```

* Install [ledgerwallet](https://github.com/LedgerHQ/ledgerctl/) and [cargo-ledger](https://github.com/LedgerHQ/cargo-ledger)

```bash
# Install ledgerwallet, a Python dependency of cargo-ledger to sideload binaries on Ledger devices
pip install ledgerwallet
# Install latest cargo-ledger from crates.io
cargo install cargo-ledger
# Run cargo-ledger command to install custom target files on the custom nightly toolchain
cargo ledger setup
```

You are now ready to build the boilerplate app for Ledger devices !

### Building

Now that you have followed the [prerequisites](#prerequisites) guide, you can build the boilerplate with the following command executed in the root directory of the app.

```bash
cargo ledger build nanox
```

This command will build the app for the Nano X, but you can use any supported device (`nanox`, `nanosplus`, `stax`, `flex`)

### Loading

ℹ️ Your device must be connected, unlocked and the screen showing the dashboard (not inside an application).

[cargo-ledger](https://github.com/LedgerHQ/cargo-ledger) also allows you to side load the binary with the following command line executed in the root directory of the boilerplate app.

```bash
cargo ledger build nanox --load
```

As for the build command, you can replace `nanox` with `nanosplus`, `stax` or `flex`.

## Test

### Ragger functional tests

This boilerplate app comes with functional tests implemented with Ledger's [Ragger](https://github.com/LedgerHQ/ragger) test framework.

* Install the tests requirements

```bash
pip install -r tests/requirements.txt 
```

* Run the functional tests :

```shell
pytest tests/ --tb=short -v --device {nanosp | nanox | stax | flex}
```

### Emulator

You can also run the app directly on the [Speculos emulator](https://github.com/LedgerHQ/speculos)

```bash
speculos --model nanox target/nanox/release/app-boilerplate-rust
```

## Continuous Integration

The following workflows are executed in [GitHub Actions](https://github.com/features/actions) :

* Ledger guidelines enforcer which verifies that an app is compliant with Ledger guidelines. The successful completion of this reusable workflow is a mandatory step for an app to be available on the Ledger application store. More information on the guidelines can be found in the repository [ledger-app-workflow](https://github.com/LedgerHQ/ledger-app-workflows)
* Compilation of the application for all supported devices in the [ledger-app-builder](https://github.com/LedgerHQ/ledger-app-builder) docker image
* End-to-end tests with the [Speculos](https://github.com/LedgerHQ/speculos) emulator and [ragger](https://github.com/LedgerHQ/ragger) (see [tests/](tests/))
* Various lint checks :
  * Source code lint checks with `cargo fmt`
  * Python functional test code lint checks with `pylint` and `mypy`
