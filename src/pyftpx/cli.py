from __future__ import annotations

import argparse
from pathlib import Path

from .transfer import receive_one
from .transfer import send_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyftpx")
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="Send a file with PyFTPX")
    send.add_argument("file")
    send.add_argument("--host", required=True)
    send.add_argument("--port", type=int, default=40404)
    send.add_argument("--timeout", type=float, default=2.0)

    recv = sub.add_parser("receive", help="Receive a file with PyFTPX")
    recv.add_argument("--bind", default="0.0.0.0")
    recv.add_argument("--port", type=int, default=40404)
    recv.add_argument("--out", default=".")
    recv.add_argument("--timeout", type=float, default=2.0)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "send":
        send_file(args.file, args.host, args.port, timeout=args.timeout)
        print(f"sent: {Path(args.file).resolve()}")
        return 0
    if args.command == "receive":
        output_path = receive_one(args.bind, args.port, args.out, timeout=args.timeout)
        print(f"received: {output_path.resolve()}")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
