This application uses authentication as a method to ascertain the safety of external, hard to verify pieces of data, like:
- output addresses in transactions
- xpubs during wallet policy registration


## Key derivation

The root identity key is derived at the following derivation path:

    `m/1229210958'`

The *i*-th user identity key is derived as: `m/1229210958'/i`. Therefore, the first user identity key is `m/1229210958'/0`.

***Remark***: unhardened derivation is used for *i* in order to allow for user-level applications that might want to manage various uncorrelated identities for the same user. For simpler applications, keeping a copy of a single identity key (with an index chosen by the user, defaulting at 0), and using that key to sign for all objects is probably enough.

## Signing devices

If a hardware signing device is used to manage the HD seed, then:

- the private key root identity key *should never leave the device*.
- exporting the root identity public key, or any user identity key, should only be done after the user's specific approval.
- the keys should only be used to sign specific messages, as prescribed by the standard.

## Signing for objects

The general format for the signing various objects using an identity key is:

    msg = SIGN_MAGIC || length(MSG_TYPE_PREFIX) || MSG_TYPE_PREFIX || length(object) || object

where:
- `SIGN/MAGIC` is the fixed byte sequence `\x09IDEN/SIGN`;
- `MSG_TYPE_PREFIX` depends on the kind of object that is being signed;
- `object` is in the binary format specified for that kind of item

### Authenticated object

Since both the object and the signature are typically shared with the receiver, it is convenient to define a unified standard for authenticated objects.

The binary encoding of an authenticated object is:

    AUTH_MAGIC || version || pubkey || msg || signature

where:
- `AUTH_MAGIC` is the fixed sequence `'\x09IDEN/AUTH'`;
- `version` is a single byte, set to `0x00` for future extensibility;
- `pubkey` is the 33-byte compressed public key of the user identity key used for signing;
- `msg` is the full content of the signed message (as defined in the "Signing for objects" section);
- `signature` is the 64-byte Schnorr signature over `msg`. TODO: specify signature details.

## Message types

### Signing for output scripts

- `MSG_TYPE_PREFIX = "OUTPUT"`
- `object` is serialized as the entire output `scriptPubkey` in bytes

### Signing for public keys

- `MSG_TYPE_PREFIX = "XPUB"`
- `object` is serialized as 78-bytes, as specified in [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)


