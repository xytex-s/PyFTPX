from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .types import FrameType
from .types import ProtocolError


@dataclass(slots=True)
class Offer:
    filename: str
    file_size: int
    chunk_size: int
    total_chunks: int
    hash_algorithm: str
    hash_digest: bytes


def encode_tlvs(items: Iterable[tuple[int, bytes]]) -> bytes:
    payload = bytearray()
    for tag, value in items:
        if tag < 0 or tag > 0xFF:
            raise ProtocolError(f"invalid TLV tag: {tag}")
        if len(value) > 0xFFFF:
            raise ProtocolError("TLV value too large")
        payload.extend(struct.pack("!BH", tag, len(value)))
        payload.extend(value)
    return bytes(payload)


def decode_tlvs(payload: bytes) -> dict[int, bytes]:
    offset = 0
    out: dict[int, bytes] = {}
    while offset < len(payload):
        if offset + 3 > len(payload):
            raise ProtocolError("truncated TLV header")
        tag, length = struct.unpack_from("!BH", payload, offset)
        offset += 3
        if offset + length > len(payload):
            raise ProtocolError("truncated TLV value")
        out[tag] = payload[offset : offset + length]
        offset += length
    return out


def build_hello_payload(max_datagram_size: int = 1200) -> bytes:
    return encode_tlvs(
        [
            (0x01, b"pyftpx"),
            (0x02, b"0.1.0"),
            (0x03, struct.pack("!H", max_datagram_size)),
            (0x04, b"sha256"),
        ]
    )


def build_offer_payload(offer: Offer) -> bytes:
    return encode_tlvs(
        [
            (0x01, offer.filename.encode("utf-8")),
            (0x02, struct.pack("!Q", offer.file_size)),
            (0x03, struct.pack("!H", offer.chunk_size)),
            (0x04, struct.pack("!I", offer.total_chunks)),
            (0x05, offer.hash_algorithm.encode("utf-8")),
            (0x06, offer.hash_digest),
        ]
    )


def parse_offer_payload(payload: bytes) -> Offer:
    tlvs = decode_tlvs(payload)
    required_tags = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    missing = [tag for tag in required_tags if tag not in tlvs]
    if missing:
        raise ProtocolError(f"offer missing required tags: {missing}")
    filename = Path(tlvs[0x01].decode("utf-8")).name
    file_size = struct.unpack("!Q", tlvs[0x02])[0]
    chunk_size = struct.unpack("!H", tlvs[0x03])[0]
    total_chunks = struct.unpack("!I", tlvs[0x04])[0]
    hash_algorithm = tlvs[0x05].decode("utf-8")
    hash_digest = tlvs[0x06]
    return Offer(
        filename=filename,
        file_size=file_size,
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        hash_algorithm=hash_algorithm,
        hash_digest=hash_digest,
    )


def build_accept_payload(accepted: bool, reason: str = "") -> bytes:
    items: list[tuple[int, bytes]] = [(0x01, b"\x01" if accepted else b"\x00")]
    if reason:
        items.append((0x02, reason.encode("utf-8")))
    return encode_tlvs(items)


def parse_accept_payload(payload: bytes) -> tuple[bool, str]:
    tlvs = decode_tlvs(payload)
    if 0x01 not in tlvs or len(tlvs[0x01]) != 1:
        raise ProtocolError("accept decision missing or malformed")
    accepted = tlvs[0x01] == b"\x01"
    reason = tlvs.get(0x02, b"").decode("utf-8", errors="replace")
    return accepted, reason


def build_data_payload(seq: int, chunk_size: int, chunk: bytes) -> bytes:
    offset_low32 = (seq * chunk_size) & 0xFFFFFFFF
    return struct.pack("!I", offset_low32) + chunk


def parse_data_payload(payload: bytes) -> tuple[int, bytes]:
    if len(payload) < 4:
        raise ProtocolError("data payload too short")
    offset_low32 = struct.unpack("!I", payload[:4])[0]
    return offset_low32, payload[4:]


def build_ranges_payload(ranges: list[tuple[int, int]]) -> bytes:
    body = bytearray(struct.pack("!H", len(ranges)))
    for start, end in ranges:
        body.extend(struct.pack("!II", start, end))
    return bytes(body)


def parse_ranges_payload(payload: bytes) -> list[tuple[int, int]]:
    if len(payload) < 2:
        raise ProtocolError("ranges payload too short")
    count = struct.unpack_from("!H", payload, 0)[0]
    expected = 2 + count * 8
    if len(payload) != expected:
        raise ProtocolError("ranges payload size mismatch")
    out: list[tuple[int, int]] = []
    offset = 2
    for _ in range(count):
        start, end = struct.unpack_from("!II", payload, offset)
        offset += 8
        out.append((start, end))
    return out


def build_fin_payload(last_seq: int, digest: bytes) -> bytes:
    return encode_tlvs([(0x01, struct.pack("!I", last_seq)), (0x02, digest)])


def parse_fin_payload(payload: bytes) -> tuple[int, bytes]:
    tlvs = decode_tlvs(payload)
    if 0x01 not in tlvs or 0x02 not in tlvs:
        raise ProtocolError("fin payload missing required tags")
    if len(tlvs[0x01]) != 4:
        raise ProtocolError("fin last seq malformed")
    return struct.unpack("!I", tlvs[0x01])[0], tlvs[0x02]


def build_fin_ack_payload(verified: bool, digest: bytes) -> bytes:
    return encode_tlvs([(0x01, b"\x01" if verified else b"\x00"), (0x02, digest)])


def parse_fin_ack_payload(payload: bytes) -> tuple[bool, bytes]:
    tlvs = decode_tlvs(payload)
    if 0x01 not in tlvs or 0x02 not in tlvs:
        raise ProtocolError("fin_ack payload missing required tags")
    if len(tlvs[0x01]) != 1:
        raise ProtocolError("fin_ack status malformed")
    return tlvs[0x01] == b"\x01", tlvs[0x02]


def is_frame_type(value: int, expected: FrameType) -> bool:
    return int(value) == int(expected)
