# Vanadium App Client Sdk

The `vanadium-client-sdk` crate is the V-App client SDK. V-App clients are built using it.

It provides functionality for:

- Registering a V-App in the device's persistent store (requires user approval).
- Starting a registered V-App.
- Low level communication (send/receive data to the V-App)
- Management of page commit/retrieval for the VM.
