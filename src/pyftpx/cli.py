from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyftpx")
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="Send a file with PyFTPX")
    send.add_argument("file")
    send.add_argument("--host", required=True)
    send.add_argument("--port", type=int, default=40404)

    recv = sub.add_parser("receive", help="Receive a file with PyFTPX")
    recv.add_argument("--bind", default="0.0.0.0")
    recv.add_argument("--port", type=int, default=40404)
    recv.add_argument("--out", default=".")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "send":
        raise NotImplementedError("Sender not implemented yet")
    if args.command == "receive":
        raise NotImplementedError("Receiver not implemented yet")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
