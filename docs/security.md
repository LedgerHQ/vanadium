The goal of Vanadium is to provide an abstraction layer that allows to run apps in the VM with a security model that is as close as possible to the security that apps running natively inside the secure enclave benefit of.

This document discusses how this is achieved, and an important caveat to take into account to avoid risks.

# Memory

## Caveat: leak of memory access pattern

> **⚠️ Important Exception:**<br>
> The **_memory access pattern_** — that is, where the app reads or writes in memory — **is not hidden** during execution of V-Apps in the Vanadium VM.

> **Safety rules:**<br>
> **- Do not implement cryptography without fully understanding the security implications**.<br>
> **- Do not use cryptographic libraries that are not written for Vanadium**.

This is an important difference compared to code running natively inside a secure enclave. The client can see some partial information about the memory accesses (particularly, what memory pages are accessed).

Therefore, certain cryptographic implementations where the memory access pattern depends on secrets information are unsafe. An example of unsafe code would be a lookup table indexed by bits derived from private keys.

The [app-sdk](../app-sdk) provides safe implementations for the common cryptographic requirements. Therefore, most apps do not need to implement any cryptographic algorithm at all - rather, they would build on top of the `app-sdk` or other libraries written for Vanadium.

## Security of outsourced memory

The Vanadium VM app implemented on Ledger devices outsources to the client (contained in the [`vanadium-client-sdk`](../client-sdk)) the storage of the V-Apps' RAM during execution.

However, the client runs on an untrusted host machine. The following countermeasures are implemented in Vanadium to prevent malicious behaviours:
- The memory of the app is organized in 256-byte pages, which are kept in the leaves of a Merkle tree. The client is responsible for keeping a copy of the entire Merkle tree, while the Vanadium VM app only stores the latest version of the Merkle root. Whenever a page is retrieved from the client, the client must respond with the content of the page, and the corresponding Merkle proof. The VM aborts if the proof is invalid.
- Pages for read-write memory are encrypted on the device *before* being sent to the client for storage. The client must respond with a Merkle proof that proves the computation of the new Merkle root. The VM aborts if the proof is invalid; otherwise, it updates the Merkle root.

# App binary

Before a V-App can be used with the Vanadium VM on a real device, it must be _registered_.

Registration allows the user to trust the V-App hash from that moment onward. During registration, the user can inspect the V-App's name, version and hash, and compare it with the expected one from a trusted source.

See [manifest.md](manifest.md) for more information about the V-App hash.

Once the user approves, the V-App is stored in a persistent registry on the device. The Vanadium VM app can store up to 32 registered V-Apps. If a V-App with the same name is already registered, it will be replaced with the new version.

When launching a V-App, the Vanadium VM verifies that the V-App hash matches one of the registered entries before allowing execution.

Note: The V-App registry is cleared if the Vanadium app is deleted or reinstalled.