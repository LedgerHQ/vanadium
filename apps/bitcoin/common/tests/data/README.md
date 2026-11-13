# Test vectors

Official test vectors, copied unmodified from the [bips](https://github.com/bitcoin/bips)
repository at commit `b34d9f751791d4feb22feff4f2ed00bcac83961b`, except for BIP-375's, from commit
`927b6de9915c9262615a6399de51b200f81e5aa4`. They are licensed as their BIPs, under BSD-2-Clause.

| File | Source |
|---|---|
| `bip352/send_and_receive_test_vectors.json` | `bip-0352/send_and_receive_test_vectors.json` (BIP-352 v1.1.2) |
| `bip374/test_vectors_generate_proof.csv` | `bip-0374/test_vectors_generate_proof.csv` (BIP-374 v0.3.1) |
| `bip374/test_vectors_verify_proof.csv` | `bip-0374/test_vectors_verify_proof.csv` (BIP-374 v0.3.1) |
| `bip375/bip375_test_vectors.json` | `bip-0375/bip375_test_vectors.json` (BIP-375 v0.1.2, vectors v1.1) |

BIP-375's reference validator and test vectors assign `k` to the outputs to each scan key in
output order, while its text sorts their codes; we follow the vectors (see
`silent_payments::recipients`).
