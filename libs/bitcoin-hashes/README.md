This crate is mostly a clone of [bitcoin_hashes](https://github.com/rust-bitcoin/rust-bitcoin/tree/master/hashes), cloned at release v0.14.0 (commit: [9df59639cec214bd9363d426335923611a304119](https://github.com/rust-bitcoin/rust-bitcoin/tree/9df59639cec214bd9363d426335923611a304119)).

## Rationale

`bitcoin_hashes` natively implements all th hash functions primitives. However, in Vanadium V-Apps, we want to use the implementations provided in the V-App SDK in order to take advantage of the native implementations provided via ECALLs.

## Licence

The code in this crate is liberally adapted from original crate from the rust-bitcoin repository, and dual-licensed as Apache License v2, and Creative Commons Zero v1.0 Universal.
