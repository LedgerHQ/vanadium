"""BIP-388 WalletPolicy: descriptor template + key information.

Mirrors the Rust ``WalletPolicy`` type, including the consensus-style
serialization used for the registration HMAC.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Sequence

from .descriptor import (
    MAX_BIP32_DERIVATION_PATH_LEN,
    MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN,
    MAX_SERIALIZED_KEY_COUNT,
    DescriptorTemplate,
    KeyInformation,
    KeyOrigin,
    ParseError,
    ParseErrorKind,
)
from .descriptor import to_descriptor as _to_descriptor
from .xpub import Xpub


class DeserializeError(Exception):
    """Raised on malformed WalletPolicy byte streams."""


class SegwitVersion(Enum):
    Legacy = "Legacy"
    SegwitV0 = "SegwitV0"
    Taproot = "Taproot"

    def is_segwit(self) -> bool:
        return self in (SegwitVersion.SegwitV0, SegwitVersion.Taproot)


# ---------------------------------------------------------------------------
# Bitcoin-consensus VarInt
# ---------------------------------------------------------------------------


def _varint_encode(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint cannot be negative")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise ValueError("varint too large")


class _Reader:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise DeserializeError("unexpected end of input")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_varint(self) -> int:
        b0 = self.read(1)[0]
        if b0 < 0xFD:
            return b0
        if b0 == 0xFD:
            return int.from_bytes(self.read(2), "little")
        if b0 == 0xFE:
            return int.from_bytes(self.read(4), "little")
        return int.from_bytes(self.read(8), "little")

    def at_end(self) -> bool:
        return self.pos == len(self.buf)


# ---------------------------------------------------------------------------
# WalletPolicy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WalletPolicy:
    """A BIP-388 wallet policy.

    Constructed via :meth:`new` so the raw descriptor template string is
    preserved byte-for-byte (it is what gets HMACed at registration).
    """

    _descriptor_template: DescriptorTemplate
    _key_information: tuple  # tuple[KeyInformation, ...]
    _descriptor_template_raw: str

    @classmethod
    def new(
        cls,
        descriptor_template_str: str,
        key_information: Sequence[KeyInformation],
    ) -> "WalletPolicy":
        descriptor_template = DescriptorTemplate.from_str(descriptor_template_str)
        return cls(
            _descriptor_template=descriptor_template,
            _key_information=tuple(key_information),
            _descriptor_template_raw=descriptor_template_str,
        )

    def descriptor_template(self) -> DescriptorTemplate:
        return self._descriptor_template

    def key_information(self) -> tuple:
        return self._key_information

    def descriptor_template_raw(self) -> str:
        return self._descriptor_template_raw

    def to_descriptor(self, is_change: bool, address_index: int) -> str:
        return _to_descriptor(
            self._descriptor_template,
            self._key_information,
            is_change,
            address_index,
        )

    def get_segwit_version(self) -> SegwitVersion:
        dt = self._descriptor_template
        if dt.kind == "Tr":
            return SegwitVersion.Taproot
        if dt.kind == "Pkh":
            return SegwitVersion.Legacy
        if dt.kind in ("Wpkh", "Wsh"):
            return SegwitVersion.SegwitV0
        if dt.kind == "Sh":
            inner = dt.args[0]
            if inner.kind in ("Wpkh", "Wsh"):
                return SegwitVersion.SegwitV0
            return SegwitVersion.Legacy
        raise ParseError(ParseErrorKind.InvalidTopLevelPolicy)

    # --- serialization ----------------------------------------------------

    def serialize(self) -> bytes:
        out = bytearray()
        raw = self._descriptor_template_raw.encode("utf-8")
        out += _varint_encode(len(raw))
        out += raw
        out += _varint_encode(len(self._key_information))
        for ki in self._key_information:
            if ki.origin_info is None:
                out += b"\x00"
            else:
                out += b"\x01"
                out += ki.origin_info.fingerprint.to_bytes(4, "big")
                out += _varint_encode(len(ki.origin_info.derivation_path))
                for step in ki.origin_info.derivation_path:
                    out += step.to_bytes(4, "little")
            out += ki.pubkey.encode()
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "WalletPolicy":
        r = _Reader(data)
        desc_len = r.read_varint()
        if desc_len > MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN:
            raise DeserializeError("Descriptor template too long")
        try:
            descriptor_template_str = r.read(desc_len).decode("utf-8")
        except UnicodeDecodeError:
            raise DeserializeError("Invalid UTF-8 in descriptor")

        key_count = r.read_varint()
        if key_count > MAX_SERIALIZED_KEY_COUNT:
            raise DeserializeError("Too many keys")

        key_information: List[KeyInformation] = []
        for _ in range(key_count):
            flag = r.read(1)[0]
            if flag == 0:
                origin = None
            elif flag == 1:
                fingerprint = int.from_bytes(r.read(4), "big")
                dp_len = r.read_varint()
                if dp_len > MAX_BIP32_DERIVATION_PATH_LEN - 2:
                    raise DeserializeError("Derivation path too long")
                path = tuple(
                    int.from_bytes(r.read(4), "little") for _ in range(dp_len)
                )
                origin = KeyOrigin(fingerprint=fingerprint, derivation_path=path)
            else:
                raise DeserializeError("Invalid key information flag")
            xpub_bytes = r.read(78)
            key_information.append(
                KeyInformation(pubkey=Xpub(xpub_bytes), origin_info=origin)
            )

        if not r.at_end():
            raise DeserializeError("Extra data after deserializing WalletPolicy")

        try:
            return cls.new(descriptor_template_str, key_information)
        except ParseError:
            raise DeserializeError(
                "Invalid descriptor template or key information"
            )
