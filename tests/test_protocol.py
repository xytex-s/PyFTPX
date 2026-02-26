from __future__ import annotations

import struct

import pytest

from pyftpx.protocol import Offer
from pyftpx.protocol import build_data_payload
from pyftpx.protocol import build_abort_payload
from pyftpx.protocol import build_offer_payload
from pyftpx.protocol import build_ranges_payload
from pyftpx.protocol import decode_tlvs
from pyftpx.protocol import encode_tlvs
from pyftpx.protocol import parse_abort_payload
from pyftpx.protocol import parse_data_payload
from pyftpx.protocol import parse_offer_payload
from pyftpx.protocol import parse_ranges_payload
from pyftpx.types import ProtocolError


def test_tlv_round_trip() -> None:
    payload = encode_tlvs([(0x01, b"alpha"), (0x02, b"beta")])
    parsed = decode_tlvs(payload)
    assert parsed == {0x01: b"alpha", 0x02: b"beta"}


def test_decode_tlvs_rejects_truncated_header() -> None:
    with pytest.raises(ProtocolError, match="truncated TLV header"):
        decode_tlvs(b"\x01\x00")


def test_decode_tlvs_rejects_truncated_value() -> None:
    malformed = struct.pack("!BH", 0x01, 4) + b"ab"
    with pytest.raises(ProtocolError, match="truncated TLV value"):
        decode_tlvs(malformed)


def test_offer_round_trip_sanitizes_filename() -> None:
    offer = Offer(
        filename="nested/path/file.txt",
        file_size=123,
        chunk_size=64,
        total_chunks=2,
        hash_algorithm="sha256",
        hash_digest=b"x" * 32,
    )

    parsed = parse_offer_payload(build_offer_payload(offer))

    assert parsed.filename == "file.txt"
    assert parsed.file_size == 123
    assert parsed.chunk_size == 64
    assert parsed.total_chunks == 2
    assert parsed.hash_algorithm == "sha256"
    assert parsed.hash_digest == b"x" * 32


def test_data_payload_round_trip() -> None:
    payload = build_data_payload(seq=3, chunk_size=1024, chunk=b"chunk")
    offset, chunk = parse_data_payload(payload)

    assert offset == 3072
    assert chunk == b"chunk"


def test_parse_data_payload_rejects_short_payload() -> None:
    with pytest.raises(ProtocolError, match="data payload too short"):
        parse_data_payload(b"abc")


def test_ranges_round_trip() -> None:
    ranges = [(0, 0), (2, 4), (8, 8)]
    payload = build_ranges_payload(ranges)
    parsed = parse_ranges_payload(payload)
    assert parsed == ranges


def test_parse_ranges_payload_rejects_size_mismatch() -> None:
    malformed = struct.pack("!HII", 2, 1, 1)
    with pytest.raises(ProtocolError, match="ranges payload size mismatch"):
        parse_ranges_payload(malformed)


def test_abort_payload_round_trip() -> None:
    payload = build_abort_payload(1001, "protocol error")
    code, message = parse_abort_payload(payload)

    assert code == 1001
    assert message == "protocol error"


def test_parse_abort_payload_rejects_malformed_code() -> None:
    payload = encode_tlvs([(0x01, b"\x01"), (0x02, b"bad")])
    with pytest.raises(ProtocolError, match="abort code malformed"):
        parse_abort_payload(payload)
