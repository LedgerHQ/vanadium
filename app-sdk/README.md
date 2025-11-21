# Vanadium App Sdk

The `vanadium-app-sdk` crate is the V-app SDK. V-app are built using it.

It provides abstractions to the services provided via calls to the OS in the target platform (ECALLs).

Functionalities include:
- Communication primitives;
- BIP32 derivations, and the master key fingerprint;
- Big integers;
- Elliptic Curve points, private keys and pubkeys;
- Hash functions;
- Basic UX functionality

# Design principles

The public exports of this library try to keep an interface that is not directly tied to the underlying ecalls. This allows to abstract differences between targets, where some ECALLs might be unavailable or different, or simply unstable and subject to change.
