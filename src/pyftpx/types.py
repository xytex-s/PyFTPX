from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


MAGIC = b"PFXP"
VERSION = 1
COMMON_HEADER_LEN = 24
DEFAULT_PORT = 40404
DEFAULT_CHUNK_SIZE = 1024
DEFAULT_TIMEOUT_SECONDS = 2.0
MAX_RETRIES = 8


class FrameType(IntEnum):
    HELLO = 0x01
    OFFER = 0x02
    ACCEPT = 0x03
    DATA = 0x04
    ACK = 0x05
    NACK = 0x06
    FIN = 0x07
    FIN_ACK = 0x08
    ABORT = 0x09
    PING = 0x0A
    PONG = 0x0B


@dataclass(slots=True)
class FrameHeader:
    version: int
    frame_type: FrameType
    flags: int
    header_len: int
    transfer_id: int
    seq: int
    payload_len: int


class ProtocolError(Exception):
    pass
