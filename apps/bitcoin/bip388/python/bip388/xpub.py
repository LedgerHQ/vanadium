"""Minimal BIP-32 xpub wrapper.

Stores the raw 78-byte serialization; only validates length and the
base58check checksum. Key material is *not* parsed or validated beyond
that — the bytes are reproduced verbatim by :meth:`Xpub.__str__`.
"""

from dataclasses import dataclass

from .base58 import b58check_decode, b58check_encode


@dataclass(frozen=True)
class Xpub:
    """Opaque 78-byte BIP-32 serialization."""

    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != 78:
            raise ValueError(f"xpub must be 78 bytes, got {len(self.raw)}")

    @classmethod
    def from_str(cls, s: str) -> "Xpub":
        raw = b58check_decode(s)
        if len(raw) != 78:
            raise ValueError(f"decoded xpub must be 78 bytes, got {len(raw)}")
        return cls(raw)

    def encode(self) -> bytes:
        """Return the 78-byte serialization (matches Rust `Xpub::encode`)."""
        return self.raw

    def __str__(self) -> str:
        return b58check_encode(self.raw)
