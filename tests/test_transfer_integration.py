from __future__ import annotations

import hashlib
import socket
import threading
import time
from pathlib import Path

import pytest

from pyftpx.codec import decode_frame
from pyftpx.codec import encode_frame
from pyftpx.protocol import build_abort_payload
from pyftpx.protocol import build_accept_payload
from pyftpx.protocol import build_fin_ack_payload
from pyftpx.protocol import build_hello_payload
from pyftpx.protocol import build_ranges_payload
from pyftpx.protocol import parse_data_payload
from pyftpx.protocol import parse_fin_payload
from pyftpx.protocol import parse_offer_payload
from pyftpx import transfer
from pyftpx.transfer import receive_one
from pyftpx.transfer import send_file
from pyftpx.types import COMMON_HEADER_LEN
from pyftpx.types import FrameHeader
from pyftpx.types import FrameType
from pyftpx.types import ProtocolError
from pyftpx.types import VERSION


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_local_send_receive_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("PyFTPX integration test payload", encoding="utf-8")

    out_dir = tmp_path / "recv"
    out_dir.mkdir(parents=True, exist_ok=True)

    host = "127.0.0.1"
    port = _free_udp_port()

    receiver_result: dict[str, Path] = {}
    receiver_errors: list[BaseException] = []

    def receiver_worker() -> None:
        try:
            receiver_result["path"] = receive_one(host, port, str(out_dir), timeout=5.0)
        except BaseException as exc:
            receiver_errors.append(exc)

    thread = threading.Thread(target=receiver_worker, daemon=True)
    thread.start()

    send_file(str(source), host, port, timeout=5.0)

    thread.join(timeout=8.0)
    assert not thread.is_alive(), "receiver thread did not complete"
    assert not receiver_errors, f"receiver errors: {receiver_errors}"

    received = receiver_result["path"]
    assert received.exists()

    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    received_hash = hashlib.sha256(received.read_bytes()).hexdigest()
    assert source_hash == received_hash


def _send_frame(
    sock: socket.socket,
    addr: tuple[str, int],
    frame_type: FrameType,
    transfer_id: int,
    seq: int,
    payload: bytes,
) -> None:
    header = FrameHeader(
        version=VERSION,
        frame_type=frame_type,
        flags=0,
        header_len=COMMON_HEADER_LEN,
        transfer_id=transfer_id,
        seq=seq,
        payload_len=len(payload),
    )
    sock.sendto(encode_frame(header, payload), addr)


def test_sender_raises_on_receiver_abort(tmp_path: Path) -> None:
    source = tmp_path / "source_abort.txt"
    source.write_text("abort path payload", encoding="utf-8")

    host = "127.0.0.1"
    port = _free_udp_port()
    ready = threading.Event()
    server_errors: list[BaseException] = []

    def receiver_abort_server() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((host, port))
                ready.set()

                hello_data, sender_addr = sock.recvfrom(65535)
                hello_header, _ = decode_frame(hello_data)
                _send_frame(sock, sender_addr, FrameType.HELLO, hello_header.transfer_id, 0, build_hello_payload())

                offer_data, sender_addr = sock.recvfrom(65535)
                offer_header, _ = decode_frame(offer_data)
                abort_payload = build_abort_payload(1001, "intentional abort for test")
                _send_frame(sock, sender_addr, FrameType.ABORT, offer_header.transfer_id, 0, abort_payload)
        except BaseException as exc:
            server_errors.append(exc)

    server_thread = threading.Thread(target=receiver_abort_server, daemon=True)
    server_thread.start()
    assert ready.wait(timeout=2.0), "test receiver server did not start"

    with pytest.raises(ProtocolError, match="peer aborted transfer"):
        send_file(str(source), host, port, timeout=2.0)

    server_thread.join(timeout=2.0)
    assert not server_thread.is_alive(), "abort server thread did not complete"
    assert not server_errors, f"receiver abort server failed: {server_errors}"


def test_sender_gap_repair_with_nack(tmp_path: Path) -> None:
    source = tmp_path / "source_gap.txt"
    payload = b"A" * 2048
    source.write_bytes(payload)

    host = "127.0.0.1"
    port = _free_udp_port()
    ready = threading.Event()
    server_errors: list[BaseException] = []
    receive_counts: dict[int, int] = {}

    def receiver_gap_server() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((host, port))
                sock.settimeout(5.0)
                ready.set()

                hello_data, sender_addr = sock.recvfrom(65535)
                hello_header, _ = decode_frame(hello_data)
                _send_frame(sock, sender_addr, FrameType.HELLO, hello_header.transfer_id, 0, build_hello_payload())

                offer_data, sender_addr = sock.recvfrom(65535)
                offer_header, offer_payload = decode_frame(offer_data)
                offer = parse_offer_payload(offer_payload)
                _send_frame(sock, sender_addr, FrameType.ACCEPT, offer_header.transfer_id, 0, build_accept_payload(True))

                received: dict[int, bytes] = {}
                dropped_seq0 = False
                sent_nack = False

                while len(received) < offer.total_chunks:
                    data, sender_addr = sock.recvfrom(65535)
                    data_header, data_payload = decode_frame(data)
                    if data_header.transfer_id != offer_header.transfer_id:
                        continue
                    if data_header.frame_type == FrameType.ABORT:
                        raise ProtocolError("sender aborted transfer")
                    if data_header.frame_type != FrameType.DATA:
                        continue
                    seq = data_header.seq
                    receive_counts[seq] = receive_counts.get(seq, 0) + 1
                    if seq == 0 and not dropped_seq0:
                        dropped_seq0 = True
                        continue
                    _, chunk = parse_data_payload(data_payload)
                    received[seq] = chunk
                    if seq == 1 and not sent_nack and 0 not in received:
                        nack_payload = build_ranges_payload([(0, 0)])
                        _send_frame(sock, sender_addr, FrameType.NACK, offer_header.transfer_id, 0, nack_payload)
                        sent_nack = True

                ack_payload = build_ranges_payload([(0, offer.total_chunks - 1)])
                _send_frame(sock, sender_addr, FrameType.ACK, offer_header.transfer_id, 0, ack_payload)

                deadline = time.monotonic() + 5.0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("FIN not received")
                    sock.settimeout(remaining)
                    fin_data, sender_addr = sock.recvfrom(65535)
                    fin_header, fin_payload = decode_frame(fin_data)
                    if fin_header.frame_type != FrameType.FIN:
                        continue
                    break
                _, sender_digest = parse_fin_payload(fin_payload)

                assembled = bytearray(offer.file_size)
                for seq, chunk in received.items():
                    offset = seq * offer.chunk_size
                    assembled[offset : offset + len(chunk)] = chunk
                local_digest = hashlib.sha256(bytes(assembled)).digest()
                verified = local_digest == offer.hash_digest == sender_digest
                fin_ack_payload = build_fin_ack_payload(verified, local_digest)
                _send_frame(sock, sender_addr, FrameType.FIN_ACK, offer_header.transfer_id, 0, fin_ack_payload)
                time.sleep(0.2)
        except BaseException as exc:
            server_errors.append(exc)

    server_thread = threading.Thread(target=receiver_gap_server, daemon=True)
    server_thread.start()
    assert ready.wait(timeout=2.0), "test receiver server did not start"

    send_file(str(source), host, port, timeout=2.0)

    server_thread.join(timeout=2.0)
    assert not server_thread.is_alive(), "gap receiver thread did not complete"
    assert not server_errors, f"gap receiver failed: {server_errors}"
    assert receive_counts.get(0, 0) > 1, "expected retransmit for missing seq 0"


def test_sender_adaptive_rto_reduces_retransmits(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "source_rto.txt"
    payload = b"B" * (transfer.DEFAULT_CHUNK_SIZE * 3)
    source.write_bytes(payload)

    monkeypatch.setattr(transfer, "WINDOW_SIZE", 1)
    monkeypatch.setattr(transfer, "INITIAL_RTO_SECONDS", 0.05)
    monkeypatch.setattr(transfer, "MIN_RTO_SECONDS", 0.02)
    monkeypatch.setattr(transfer, "MAX_RTO_SECONDS", 1.0)

    host = "127.0.0.1"
    port = _free_udp_port()
    ready = threading.Event()
    server_errors: list[BaseException] = []
    receive_counts: dict[int, int] = {}

    def receiver_delayed_ack_server() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((host, port))
                sock.settimeout(5.0)
                ready.set()

                hello_data, sender_addr = sock.recvfrom(65535)
                hello_header, _ = decode_frame(hello_data)
                _send_frame(sock, sender_addr, FrameType.HELLO, hello_header.transfer_id, 0, build_hello_payload())

                offer_data, sender_addr = sock.recvfrom(65535)
                offer_header, offer_payload = decode_frame(offer_data)
                offer = parse_offer_payload(offer_payload)
                _send_frame(sock, sender_addr, FrameType.ACCEPT, offer_header.transfer_id, 0, build_accept_payload(True))

                received: dict[int, bytes] = {}
                while len(received) < offer.total_chunks:
                    data, sender_addr = sock.recvfrom(65535)
                    data_header, data_payload = decode_frame(data)
                    if data_header.transfer_id != offer_header.transfer_id:
                        continue
                    if data_header.frame_type == FrameType.ABORT:
                        raise ProtocolError("sender aborted transfer")
                    if data_header.frame_type != FrameType.DATA:
                        continue
                    seq = data_header.seq
                    receive_counts[seq] = receive_counts.get(seq, 0) + 1
                    if seq not in received:
                        _, chunk = parse_data_payload(data_payload)
                        received[seq] = chunk
                    time.sleep(0.2)
                    ack_payload = build_ranges_payload([(seq, seq)])
                    _send_frame(sock, sender_addr, FrameType.ACK, offer_header.transfer_id, 0, ack_payload)

                deadline = time.monotonic() + 5.0
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("FIN not received")
                    sock.settimeout(remaining)
                    fin_data, sender_addr = sock.recvfrom(65535)
                    fin_header, fin_payload = decode_frame(fin_data)
                    if fin_header.frame_type != FrameType.FIN:
                        continue
                    break
                _, sender_digest = parse_fin_payload(fin_payload)

                assembled = bytearray(offer.file_size)
                for seq, chunk in received.items():
                    offset = seq * offer.chunk_size
                    assembled[offset : offset + len(chunk)] = chunk
                local_digest = hashlib.sha256(bytes(assembled)).digest()
                verified = local_digest == offer.hash_digest == sender_digest
                fin_ack_payload = build_fin_ack_payload(verified, local_digest)
                _send_frame(sock, sender_addr, FrameType.FIN_ACK, offer_header.transfer_id, 0, fin_ack_payload)
                time.sleep(0.2)
        except BaseException as exc:
            server_errors.append(exc)

    server_thread = threading.Thread(target=receiver_delayed_ack_server, daemon=True)
    server_thread.start()
    assert ready.wait(timeout=2.0), "test receiver server did not start"

    send_file(str(source), host, port, timeout=5.0)

    server_thread.join(timeout=6.0)
    assert not server_thread.is_alive(), "delayed-ack receiver thread did not complete"
    assert not server_errors, f"delayed-ack receiver failed: {server_errors}"
    assert receive_counts.get(0, 0) > 1, "expected initial retransmit before RTO adapts"
    assert receive_counts.get(2, 0) == 1, "expected adaptation by final chunk"
    assert receive_counts.get(1, 0) <= receive_counts.get(0, 0)
