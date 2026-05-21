"""Minimal Base58 / Base58Check codec for BIP-32 xpub serialization.

This is the smallest amount of base58 needed to round-trip the 78-byte
BIP-32 serialization carried in `KeyInformation`. It is not a
general-purpose codec.
"""

import hashlib

_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def b58encode(data: bytes) -> str:
    n_leading_zeros = 0
    for b in data:
        if b == 0:
            n_leading_zeros += 1
        else:
            break
    n = int.from_bytes(data, "big") if data else 0
    out = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_ALPHABET[r])
    out.extend(b"1" * n_leading_zeros)
    out.reverse()
    return out.decode("ascii")


def b58decode(s: str) -> bytes:
    n_leading_ones = 0
    for c in s:
        if c == "1":
            n_leading_ones += 1
        else:
            break
    n = 0
    for c in s:
        try:
            n = n * 58 + _INDEX[ord(c)]
        except KeyError:
            raise ValueError(f"invalid base58 character {c!r}")
    payload = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * n_leading_ones + payload


def b58check_encode(data: bytes) -> str:
    return b58encode(data + _sha256d(data)[:4])


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 4:
        raise ValueError("base58check payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    if _sha256d(payload)[:4] != checksum:
        raise ValueError("invalid base58check checksum")
    return payload
