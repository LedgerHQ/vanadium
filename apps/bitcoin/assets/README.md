# Assets

Non-code files shared by the crates of the Bitcoin V-App (`app`, `client`, `common`, ...) and by
its documentation. Anything here is data, not source: it is read verbatim at runtime, embedded with
`include_bytes!` in tests, or referenced from the docs.

- [signing_policies](signing_policies) — ready-to-use signing programs (`.plc` files) that a wallet
  policy key can commit to, with a [README](signing_policies/README.md) explaining the format and
  how to use them from the CLI.
