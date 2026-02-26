from __future__ import annotations

import hashlib
import socket
import threading
from pathlib import Path

import pytest

from pyftpx.codec import decode_frame
from pyftpx.codec import encode_frame
from pyftpx.protocol import build_abort_payload
from pyftpx.protocol import build_hello_payload
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
