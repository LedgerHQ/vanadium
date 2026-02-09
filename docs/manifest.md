The Manifest contains all the information to unambiguously identify a V-App that Vanadium can run.

As the code of the V-Apps is provided externally from the untrusted client, the Manifest is used to compute a single _V-App hash_ that defines exactly what the app is.

While the exact specifications of the Manifest are (at this stage) are still likely to change before Vanadium 1.0, the V-App hash will likely commit to:

- The manifest version (for future upgradeability)
- The V-App's name and version
- The V-App's entry point
- the start, end and the initial Merkle root of the code, data and stack segments of the binary.
- the number of persistent storage slots, if needed.

The [cargo-vnd](../cargo-vnd) tool computes most of those fields from the compiled binary, producing a packaged binary that contains the Manifest added to it.

## Cargo.toml manifest fields

Some of the fields of the Manifest are specified in the V-App's `Cargo.toml`. The `cargo-vnd` will include them in the Manifest while preparing the packaged V-App binary.

Currently, only two fields are defined: `name` and `stack_size`.

The name is shown when the V-App is registered onto the device.

```
[package.metadata.vapp]
name = "My App"
stack_size = 131072
n_storage_slots = 2
```

If omitted:
- `stack_size` defaults to 65536 bytes.
- `n_storage_slots` defaults to 0.

