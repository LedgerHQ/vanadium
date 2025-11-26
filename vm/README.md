This is the Vanadium Risc-V VM app. For now, it's just boilerplate.

# Vanadium VM for Ledger devices

![Rule enforcer](https://github.com/LedgerHQ/app-boilerplate-rust/actions/workflows/guidelines_enforcer.yml/badge.svg) ![Build and tests](https://github.com/LedgerHQ/app-boilerplate-rust/actions/workflows/build_and_functional_tests.yml/badge.svg)

# Quick start guide

# Vanadium binaries

You can download precompiled binaries, or compile them yourself as described below.

## Precompiled binaries

You can download the latest version of the binaries from GitHub by launching the `download_vanadium.sh` script in the `vm` folder:

```bash
$ cd vm
$ bash download_vanadium.sh
```

## Build with the Ledger VS Code extension

You can quickly setup a development environment on any platform (macOS, Linux or Windows) to build and test your application with [Ledger's VS Code extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).

By using Ledger's own developer tools [Docker image](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools), the extension allows you to **build** your apps with the latest SDK, **test** them on **Speculos** and **load** them on any supported device.

* Install and run [Docker](https://www.docker.com/products/docker-desktop/).
* Make sure you have an X11 server running :
  * On Ubuntu Linux, it should be running by default.
  * On macOS, install and launch [XQuartz](https://www.xquartz.org/) (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  * On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/) (make sure to configure it to disable access control).
* Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
* Open a terminal and clone `vanadium` with `git clone git@github.com:LedgerHQ/vanadium.git`.
* Open the `vm` folder in the `vanadium` repository with VSCode.
* Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b` (`command + shift + b` on a Mac) to build the app, or load it on a device.

We recommend not to run the Vanadium app from the VSCode extension. Instead, install the Speculos emulator locally.

## Emulator

After downloading the binaries or building, you can run the app directly on the [Speculos emulator](https://github.com/LedgerHQ/speculos). For example, if you build the app for Flex:

```bash
speculos target/flex/release/app-vanadium
```

If you use [just](https://github.com/casey/just), you can also run:

```bash
just run-flex  # or run-nanosplus, run-nanox, run-stax, run-apex_p
```
