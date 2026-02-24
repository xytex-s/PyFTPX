from __future__ import annotations

import argparse
import hashlib
import threading
import time
from pathlib import Path

from .transfer import receive_one
from .transfer import send_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m pyftpx.smoke_test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=40404)
    parser.add_argument("--sample-file", default="sample_py.txt")
    parser.add_argument("--out", default="recv_py")
    parser.add_argument("--payload", default="PyFTPX python smoke test payload")
    parser.add_argument("--receiver-timeout", type=float, default=30.0)
    parser.add_argument("--sender-timeout", type=float, default=10.0)
    return parser


def run_smoke_test(
    host: str,
    port: int,
    sample_file: str,
    out_dir: str,
    payload: str,
    receiver_timeout: float,
    sender_timeout: float,
) -> tuple[Path, Path]:
    sample_path = Path(sample_file)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    sample_path.write_text(payload, encoding="utf-8")

    receiver_result: dict[str, Path] = {}
    receiver_error: list[BaseException] = []

    def receiver_worker() -> None:
        try:
            receiver_result["path"] = receive_one(host, port, str(out_path), timeout=receiver_timeout)
        except BaseException as exc:  # pragma: no cover - passthrough for CLI visibility
            receiver_error.append(exc)

    receiver_thread = threading.Thread(target=receiver_worker, daemon=True)
    receiver_thread.start()
    time.sleep(0.5)

    send_file(str(sample_path), host, port, timeout=sender_timeout)

    receiver_thread.join(timeout=receiver_timeout + 5)
    if receiver_thread.is_alive():
        raise TimeoutError("receiver thread did not complete")
    if receiver_error:
        raise receiver_error[0]

    received_path = receiver_result.get("path")
    if not received_path:
        raise RuntimeError("receiver did not produce an output path")

    source_hash = hashlib.sha256(sample_path.read_bytes()).hexdigest()
    received_hash = hashlib.sha256(received_path.read_bytes()).hexdigest()
    if source_hash != received_hash:
        raise ValueError(f"hash mismatch: source={source_hash} received={received_hash}")

    return sample_path, received_path


def main() -> int:
    args = build_parser().parse_args()
    sample_path, received_path = run_smoke_test(
        host=args.host,
        port=args.port,
        sample_file=args.sample_file,
        out_dir=args.out,
        payload=args.payload,
        receiver_timeout=args.receiver_timeout,
        sender_timeout=args.sender_timeout,
    )

    print(f"sent: {sample_path.resolve()}")
    print(f"received: {received_path.resolve()}")
    print("Python smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
