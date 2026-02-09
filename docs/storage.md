V-Apps can use persistent storage on the device, using the `storage` module in the V-App SDK.

Storage is organized in 32-byte slots, and it is currently limited to at most 4 slots per application. Therefore, V-Apps can store a total of 128 bytes.

V-Apps that want to use storage must declare it using the `n_storage_slots` in the [manifest](manifest) in their Cargo.toml.

## Needing more storage?

A V-App that needs more than the small amount of supported persistent storage might achieve a similar effect by outsourcing the (encrypted) storage to the client, and only storing a commitment in the actual V-App storage.

> **⚠️ Important:**<br>
Like for Vanadium's code and RAM outsourcing, depending on the implementation, **this might leak the storage access pattern**, therefore developers need to be careful to make sure that this does not have security implications. See [security.md](security.md) for a discussion on this topic.

Most real-world usages of persistent storage are not related to low-level cryptography, and are therefore not expected to be impacted by this potential side channel.
