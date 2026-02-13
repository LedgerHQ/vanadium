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

## HMAC-based proofs for the V-App code

Merkle proofs are not for free, and increase the communication cost between the Vanadium VM and the host, which negatively affects performance. In fact, for binaries larger than 64kb, the size of the Merkle proofs is larger than the size of pages themselves.

Since the code section is immutable, an alternative approach can be used for code. The core idea is that the Vanadium app can use an HMAC to re-authenticate a page hash that it has previously validated. Therefore, by just sending once all the code page hashes, the Vanadium app can verify that those hashes are correct, and send an hmac for each page that the host can store persistently. Later, whenever the Vanadium VM asks the host to provide a page and its proof, the host can respond with the stored HMAC, instead of the Merkle proof.

The Vanadium app securely generates a random 32-byte secret key `auth_key` the first time it is executed.

For a V-App with Manifest hash `vapp_hash`, the `app_auth_key` is computed as `SHA256(SHA256("VND_APP_AUTH_KEY") ‖ auth_key ‖ vapp_hash)`.

In the following, the page index `i` is a 32-bit number, and `be32(i)` is the 4-byte big-endian encoding.

Here are the details of the protocol to produce the valid HMACs for the host to store on the client side:
- The Vanadium app generates a random 32-byte secret `ephemeral_sk`.
- For each page index `i` in increasing order:
  - the host sends the leaf hash `page_hash_i` of page `i`.
  - the Vanadium app:
    - computes the encryption key for the `i`-th page: `page_sk_i = SHA256("VND_HMAC_MASK" ‖ ephemeral_sk ‖ be32(i))`.
    - computes the `hmac_i = HMAC-SHA256(key = app_auth_key, msg = "VND_PAGE_TAG" ‖ vapp_hash ‖ be32(i) ‖ page_hash_i)`.
    - sends to the host `encrypted_hmac_i = hmac_i ⊕ page_sk_i`.
- Once all the page hashes are sent, the Vanadium app validates whether the Merkle root for the code section computed from the provided page hashes matches the one in the Manifest. 
- If the Merkle root computed from the page hashes provided by the client matches the one in the V-App Manifest, the Vanadium app sends `ephemeral_sk` to the host. Otherwise, the VM aborts.

Once the protocol completes successfully, the host can independently recompute `page_sk_i` and therefore `hmac_i` for each `i`.

# Persistent storage

For apps that store any data in persistent storage, Vanadium guarantees isolation between V-Apps, preventing one app to access the store of other apps.

The stored data has the same physical tamper-resistance as the Vanadium app binary itself.
