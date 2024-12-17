# DISCLAIMER

:warning: | THIS IS AN EXPERIMENTAL PROJECT. IT IS INSECURE AT THIS STAGE<br/>Please don't start depending on it, and do not use it in production. Large parts of this project are subject to change. | :warning:
:---: | :--- | :---

---

# Vanadium

Vanadium is a Risc-V Virtual Machine that runs in an embedded Secure Element.

<img align="right" src="docs/assets/vanadium_logo.png" alt="Vanadium Logo" style="width: 50%; min-width: 200px; max-width: 280px"/>

By outsourcing encrypted, authenticated pages to an untrusted client, it allows to run applications (V-Apps) in the secure element without worrying about the limitations of the embedded platform.

You can write V-Apps without worrying about binary size and memory usage: only the code actually used at runtime will be sent to the device for execution, and page swapping with the client happens transparently between the VM and the VM client.

During development, you will write and test code natively, without relying on an external emulator. This simplifies writing, testing and deploying your code while keeping the majority of it generic, and not tied to a specific platform.

# Repository structure

This repository is organized in a monorepo structure.

* [docs](docs) - Architecture and technical documentation
* [VM](vm) <small>[<tt>arm</tt>], no-std</small> - The Vanadium Ledger app. It contains the actual Virtual Machine.
* [app-sdk](app-sdk) <small>[<tt>riscv</tt>], no_std</small> - Vanadium V-App SDK. It is used by V-Apps to access all the system services.
* [client-sdk](client-sdk) <small>[<tt>native</tt>]</small> - Vanadium V-App client SDK. V-App Clients use it as a base for their own client crates.
* [common](common) <small>[<tt>arm|riscv|native</tt>], no_std</small> - Any code that is shared among two or more of the above crates.
* [apps](apps) - Complete V-Apps, and their clients
  * [test](apps/test) - Simple V-App to test the Vanadium.
  * [sadik](apps/sadik) - A V-App specifically designed to test the various functionality of the Vanadium V-App SDK, and particularly the ECALLs.
  * [bitcoin](apps/bitcoin) - Grandiose things will happen here, but it's mostly empty at this stage.

In VSCode, opening the [vanadium.code-workspace](vanadium.code-workspace) is the most convenient way to work with this repository.

## License

This project is licensed under the [Apache Licence v2.0](LICENSE).
