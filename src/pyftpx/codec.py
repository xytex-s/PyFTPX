from __future__ import annotations

from .types import FrameHeader


def encode_frame(header: FrameHeader, payload: bytes) -> bytes:
    raise NotImplementedError("Implement per docs/protocol-spec.md")


def decode_frame(datagram: bytes) -> tuple[FrameHeader, bytes]:
    raise NotImplementedError("Implement per docs/protocol-spec.md")
