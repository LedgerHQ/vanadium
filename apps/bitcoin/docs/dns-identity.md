This document specifies how an *identity key* (as defined in [identity.md](identity.md)) can be
published in the DNS and proven to a signing device with a DNSSEC proof, removing the need for an
explicit registration ceremony.

It is a variant of [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki): the
DNS record encodes a **public key** instead of a payment destination.

# Motivation

BIP-353 puts a payment destination in a DNS TXT record, and the payer's software resolves
`user@domain` into a `bitcoin:` URI. For a hardware signing device this has an awkward consequence:
an on-chain address must be fresh for each payment, so the DNS record has to be rewritten
constantly. BIP-353 acknowledges this, requiring that such records "SHOULD be rotated as regularly
as possible" and use "a relatively short DNS TTL".

Publishing an identity public key instead inverts the tradeoff:

- The DNS record is **static and long-lived**. It is written once, can use a long TTL, and the proof
  of it may be cached or pinned for as long as its signatures are valid.
- The address is delivered **out of band**, together with a signature from the published key over
  that address' `scriptPubKey`. Freshness is a property of the address, not of the DNS.

The device then needs only one thing from the DNS: a globally verifiable binding from a
human-readable name to a key. Everything else — which address, which amount, when — is carried by the
signature machinery that already exists in this application, unchanged.

# Relationship to BIP-353

The following are kept exactly as in BIP-353:

- the record location `user.user._bitcoin-payment.<domain>`;
- a single TXT resource record, whose RDATA is one or more character-strings of at most 255 bytes
  each, reconstructed by concatenation in RDATA order without separators;
- the requirement that records be DNSSEC-signed and validated to the root;
- the rule that TXT records at that label which do not begin (ignoring case) with `bitcoin:` are
  ignored, and that two or more records which do makes the label invalid;
- punycode ([RFC 3492](https://www.rfc-editor.org/rfc/rfc3492),
  [RFC 5891](https://www.rfc-editor.org/rfc/rfc5891)) for non-ASCII identifiers;
- the display convention `₿user@domain` for a verified name.

The following differ:

1. **Payload.** A new BIP-21 query parameter `idkey` carries an identity public key rather than a
   payment destination (see [The DNS record](#the-dns-record)). It MAY appear alongside an address,
   `sp=` or `lno=`, so that a record remains useful to BIP-353 wallets which do not understand it.
2. **Rotation and caching.** The address-reuse and rotation guidance of BIP-353 does not apply,
   because the record contains no address. A long TTL is preferred. A verifier MAY cache or pin a
   verified name-to-key binding for as long as the proof's signatures remain valid.
3. **PSBT encoding.** BIP-353 defines `PSBT_OUT_DNSSEC_PROOF` (keytype `0x35`), a *per-output* field
   proving that an output's address came from a name. Here the proof binds a *key* to a name, so it
   is carried once per key in the global map, and the per-output link is the identity signature. See
   [PSBT encoding](#psbt-encoding).
4. **Preference rule.** BIP-353 states that wallets "MUST NOT prefer to use DNS-based resolving when
   methods with explicit public keys or addresses are available". Here the DNS *is* the source of the
   explicit public key. The rule survives in a narrower form: when the same key is available both as
   a locally registered key and as a DNS-proven one, a device MUST prefer the local registration,
   which required a direct user action.
5. **Algorithm profile.** A verifier running on a constrained device supports a restricted set of
   DNSSEC algorithms; see [Validation](#validation).

# The DNS record

An identity key is published as a BIP-21 query parameter named `idkey` inside the `bitcoin:` URI of
a BIP-353 record:

    alice.user._bitcoin-payment.example.com. 3600 IN TXT "bitcoin:?idkey=idkey1qqp8n0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xqz57u8d"

The value is a [bech32m](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) string with
human-readable part `idkey`, encoding:

| Field | Size | Description |
|---|---|---|
| `version` | 1 byte | `0x00`. Reserved for future extensibility, as in the authenticated object encoding of [identity.md](identity.md). |
| `pubkey` | 33 bytes | The compressed secp256k1 public key of the identity key, with a `0x02` or `0x03` prefix. |

The encoded string is 67 characters, well within bech32's 90-character limit. The human-readable
part deliberately echoes the parameter name, as with `sp=sp1...` and `lno=lno1...`.

The example above encodes the secp256k1 generator point, which is of course not a usable identity
key; it is used here only so that the encoding is reproducible.

Rules for publishers and verifiers:

- Exactly one `idkey` parameter MUST be present. Two or more make the record invalid.
- A `version` other than `0x00`, or a payload which is not 34 bytes, makes the record invalid.
- Parameters other than `idkey` are ignored by a verifier of this specification. (The BIP-21
  treatment of `req-` parameters remains the responsibility of the payer's software, which is what
  constructs the payment; the device only ever inspects `idkey`.)
- The human-readable name is of the form `local@domain`, and MUST be ASCII. A publisher whose name
  contains non-ASCII characters MUST publish, and transport to the device, the punycode (A-label)
  form. Verifiers MUST reject non-ASCII names: rendering `xn--...` is unfriendly, but it is immune to
  homograph attacks, which a device with a limited font and a small screen cannot otherwise defend
  against.
- The name, excluding any `₿` prefix, MUST NOT exceed 255 bytes, so that it fits the one-byte length
  prefix used when it is transported.

The key is a 33-byte compressed point rather than an x-only key so that the `IdentityKey` type, the
message construction of [identity.md](identity.md), and the existing signature formats are unchanged.

# Authenticating an output

Nothing in this section is new; it is the mechanism of [identity.md](identity.md) and
[PSBT.md](PSBT.md), restated for completeness.

The holder of the identity key signs an output script as:

    msg = "\x09IDEN/SIGN" || length("OUTPUT") || "OUTPUT" || length(scriptPubKey) || scriptPubKey

with a 64-byte [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) Schnorr
signature.

Such a signature is a portable, amount-independent certificate that a script belongs to the holder of
the key. It commits to no transaction, so it may be produced ahead of time and reused. How the payer
obtains the `(address, signature)` pair is out of scope: a payment request, an invoice, an HTTPS
endpoint, or a QR code all work equally well. A device running this application already produces
exactly this pair — see the `identity_index` parameter of the `GetAddress` request.

# PSBT encoding

The chain of DNSSEC records proving the name-to-key binding is carried in the global map of the PSBT,
using the `IDAUTH` proprietary identifier defined in [PSBT.md](PSBT.md).

## Global subkey type

| Name | `<subkeytype>` | `<subkeydata>` | `<valuedata>` |
|---|---|---|---|
| DNSSEC identity key | `PSBT_IDAUTH_GLOBAL_DNSSEC_IDENTITY_KEY = 0x01` | `<33-byte identity pubkey>` | `<1-byte name length> <name> <RFC 9102 AuthenticationChain>` |

where `name` is the human-readable name without any `₿` prefix, and the chain is an
[RFC 9102](https://www.rfc-editor.org/rfc/rfc9102) `AuthenticationChain`: a sequence of uncompressed
wire-format DNS resource records, in no particular order, including all the RRSIG records needed to
validate them.

The `<name><chain>` layout is deliberately byte-identical to the value of BIP-353's
`PSBT_OUT_DNSSEC_PROOF`, so that a single parser can serve both should the per-output field be
supported later.

The per-output field is **unchanged**: an output is still authenticated by
`PSBT_IDAUTH_OUT_SIGNATURE = 0x00` with `auth_tag = 0x00`, exactly as for a locally registered key.
Only the way in which the public key becomes trusted differs. There is no new `auth_tag`.

## Rules

- The same public key MUST NOT appear both as a registered identity key (`0x00`) and as a DNSSEC
  identity key (`0x01`). A signer encountering both MUST abort.
- A malformed or invalid proof MUST abort signing, consistently with the existing rule for invalid
  output authentication signatures. A *valid* proof for a key which signs no output is not an error;
  it is simply unused.
- A signer MAY bound the number of proofs it is willing to validate per transaction, and the size of
  each chain, and MUST abort rather than truncate when a bound is exceeded.

# Validation

Given a name, a chain, and the public key it is claimed to bind, a verifier MUST:

1. Parse the chain as an RFC 9102 `AuthenticationChain`.
2. Validate every signature up to a trust anchor for the root zone which is built into the verifier.
   A verifier MUST NOT delegate any part of this validation to a remote resolver, and MUST NOT accept
   a chain which does not reach the root.
3. Reject any RRSIG whose algorithm is not one of:

   | Number | Algorithm |
   |---|---|
   | 8 | RSA/SHA-256 |
   | 10 | RSA/SHA-512 |
   | 13 | ECDSA P-256/SHA-256 |
   | 14 | ECDSA P-384/SHA-384 |

   This satisfies BIP-353's requirement to reject SHA-1 signatures (algorithms 5 and 7) and RSA keys
   shorter than 1024 bits. Algorithm 15 (Ed25519) is **not** supported by this profile; a publisher
   whose zone is signed with it cannot be verified by this application.
   A DS record with digest type 1 (SHA-1) MUST be ignored whenever a SHA-256 digest is available for
   the same delegation.
4. Enforce the validity period of every RRSIG in the chain against the current time `now`:
   the latest inception MUST NOT be later than `now`, and the earliest expiration MUST NOT be earlier
   than `now - 3600`. The one-hour allowance is the one BIP-353 grants for clock skew.

   A device with no trusted clock necessarily obtains `now` from its host, which is not trusted. Such
   a device MUST display the date it used, so that a user can notice a host which is presenting a
   long-expired proof. The residual risk is described under
   [Security considerations](#security-considerations).
5. Derive the expected owner name from the human-readable name: for `alice@example.com`, this is
   `alice.user._bitcoin-payment.example.com.`. The TXT resource record set MUST be at that name,
   after resolving any CNAME or DNAME indirection, each link of which MUST itself be signed.
6. Reconstruct the URI from the TXT record following BIP-353: concatenate the character-strings of
   the record's RDATA in order without separators; ignore records which do not begin, ignoring case,
   with `bitcoin:`; and treat the label as invalid if more than one record does.
7. Extract the `idkey` parameter, decode it, and require the resulting public key to equal the key
   the proof is claimed to bind. A mismatch MUST abort.

A verifier MAY additionally reject a proof whose leaf record was served by a wildcard, but is not
required to: a wildcard-served record is identified by the RRSIG `labels` field being smaller than
the number of labels in the owner name, and proving that no closer match exists requires NSEC or
NSEC3 records in the chain.

# Device behaviour

A device which has verified a name-to-key binding, and which then verifies an output authentication
signature from that key, SHOULD display the name in place of the raw address, and MUST make the raw
address available to the user on request.

It MUST distinguish, on screen, a name proven by DNSSEC from a name chosen by the user during a local
registration. The user's judgement about what a name means depends entirely on where the name came
from: a locally registered `Bob` is a name the user typed, whereas `₿bob@example.com` is a claim by
whoever controls `example.com`. Following BIP-353, a DNSSEC-verified name SHOULD be prefixed with
`₿`. On a device whose font cannot render U+20BF, an unambiguous textual marker MUST be used instead.

Verification of the binding does not, by itself, justify skipping user confirmation of an output.

# Security considerations

- **The DNS hierarchy becomes part of the trusted computing base.** Every zone on the path — the
  root, the TLD, and the publisher's own zone — can produce a valid proof for a key of its choosing,
  and so can a registrar with control over the delegation. This is strictly weaker than a locally
  registered key, and is the reason the two must be distinguishable on screen.
- **Without a trusted clock, expiry is advisory.** A host can present a proof whose signatures
  expired long ago, and the only defence is the displayed date. Consequently, revoking a compromised
  identity key by removing it from the DNS is not reliably enforceable on a device which has no time
  source; the mitigation available to a publisher is to sign with short RRSIG validity periods, which
  bounds how long a stale proof stays plausible to a user checking the displayed date.
- **A signature is a bearer credential for a script.** Anyone who obtains the `(scriptPubKey,
  signature)` pair can cause a device to label that script with the name. This is not a weakness:
  the signature asserts that the script belongs to the holder of the key, and that assertion remains
  true regardless of who repeats it. It says nothing about the amount, and nothing about the rest of
  the transaction.
- **Names are attacker-chosen strings.** A publisher controls the local part of the name entirely.
  Verifiers reject non-ASCII names, and a device with a small screen should take care that a long
  name cannot push the address out of view.

# Limitations of this profile

- Ed25519-signed zones (DNSSEC algorithm 15) cannot be verified.
- The binding is not persisted on the device: every transaction carries its own proof. A future
  revision may allow a verified binding to be stored, in which case the freshness rules above become
  load-bearing in a way they are not today.
- Only output scripts are covered. The `XPUB` message type of [identity.md](identity.md), used to
  label cosigner keys during account registration, still requires a locally registered key.
