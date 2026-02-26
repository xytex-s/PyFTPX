from __future__ import annotations

import hashlib
import socket
import threading
from pathlib import Path

from pyftpx.transfer import receive_one
from pyftpx.transfer import send_file


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
