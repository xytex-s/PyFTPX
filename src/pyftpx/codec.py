from __future__ import annotations

import struct

from .types import FrameHeader
from .types import COMMON_HEADER_LEN
from .types import FrameType
from .types import MAGIC
from .types import ProtocolError
from .types import VERSION


_COMMON_HEADER_STRUCT = struct.Struct("!4sBBBBQII")


def encode_frame(header: FrameHeader, payload: bytes) -> bytes:
    if header.version != VERSION:
        raise ProtocolError(f"unsupported version: {header.version}")
    if header.header_len != COMMON_HEADER_LEN:
        raise ProtocolError(f"unsupported header length: {header.header_len}")
    if header.payload_len != len(payload):
        raise ProtocolError("payload_len does not match payload size")
    if header.flags < 0 or header.flags > 0xFF:
        raise ProtocolError("flags out of range")
    return _COMMON_HEADER_STRUCT.pack(
        MAGIC,
        header.version,
        int(header.frame_type),
        header.flags,
        header.header_len,
        header.transfer_id,
        header.seq,
        header.payload_len,
    ) + payload


def decode_frame(datagram: bytes) -> tuple[FrameHeader, bytes]:
    if len(datagram) < COMMON_HEADER_LEN:
        raise ProtocolError("datagram shorter than common header")
    magic, version, frame_type, flags, header_len, transfer_id, seq, payload_len = _COMMON_HEADER_STRUCT.unpack_from(
        datagram, 0
    )
    if magic != MAGIC:
        raise ProtocolError("invalid frame magic")
    if version != VERSION:
        raise ProtocolError(f"unsupported version: {version}")
    if header_len < COMMON_HEADER_LEN:
        raise ProtocolError("invalid header length")
    if len(datagram) < header_len:
        raise ProtocolError("datagram shorter than declared header length")
    payload = datagram[header_len:]
    if len(payload) != payload_len:
        raise ProtocolError("declared payload length mismatch")
    try:
        decoded_type = FrameType(frame_type)
    except ValueError as exc:
        raise ProtocolError(f"unknown frame type: {frame_type}") from exc
    return (
        FrameHeader(
            version=version,
            frame_type=decoded_type,
            flags=flags,
            header_len=header_len,
            transfer_id=transfer_id,
            seq=seq,
            payload_len=payload_len,
        ),
        payload,
    )
