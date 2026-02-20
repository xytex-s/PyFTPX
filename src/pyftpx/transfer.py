from __future__ import annotations

import hashlib
import random
import socket
from pathlib import Path

from .codec import decode_frame
from .codec import encode_frame
from .protocol import Offer
from .protocol import build_accept_payload
from .protocol import build_data_payload
from .protocol import build_fin_ack_payload
from .protocol import build_fin_payload
from .protocol import build_hello_payload
from .protocol import build_offer_payload
from .protocol import build_ranges_payload
from .protocol import is_frame_type
from .protocol import parse_accept_payload
from .protocol import parse_data_payload
from .protocol import parse_fin_ack_payload
from .protocol import parse_fin_payload
from .protocol import parse_offer_payload
from .protocol import parse_ranges_payload
from .types import COMMON_HEADER_LEN
from .types import DEFAULT_CHUNK_SIZE
from .types import DEFAULT_TIMEOUT_SECONDS
from .types import MAX_RETRIES
from .types import FrameHeader
from .types import FrameType
from .types import ProtocolError
from .types import VERSION


def _header(frame_type: FrameType, transfer_id: int, seq: int, payload: bytes) -> FrameHeader:
    return FrameHeader(
        version=VERSION,
        frame_type=frame_type,
        flags=0,
        header_len=COMMON_HEADER_LEN,
        transfer_id=transfer_id,
        seq=seq,
        payload_len=len(payload),
    )


def _send_frame(sock: socket.socket, addr: tuple[str, int], frame_type: FrameType, transfer_id: int, seq: int, payload: bytes) -> None:
    sock.sendto(encode_frame(_header(frame_type, transfer_id, seq, payload), payload), addr)


def _recv_frame(sock: socket.socket) -> tuple[FrameHeader, bytes, tuple[str, int]]:
    datagram, addr = sock.recvfrom(65535)
    header, payload = decode_frame(datagram)
    return header, payload, addr


def send_file(file_path: str, host: str, port: int, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
    source = Path(file_path)
    if not source.is_file():
        raise FileNotFoundError(source)

    data = source.read_bytes()
    digest = hashlib.sha256(data).digest()
    file_size = len(data)
    chunk_size = DEFAULT_CHUNK_SIZE
    total_chunks = (file_size + chunk_size - 1) // chunk_size
    transfer_id = random.getrandbits(64)
    remote_addr = (host, port)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)

        hello_payload = build_hello_payload()
        _send_frame(sock, remote_addr, FrameType.HELLO, transfer_id, 0, hello_payload)
        hello_header, _, hello_addr = _recv_frame(sock)
        if hello_addr != remote_addr or hello_header.transfer_id != transfer_id or not is_frame_type(hello_header.frame_type, FrameType.HELLO):
            raise ProtocolError("invalid HELLO response")

        offer = Offer(
            filename=source.name,
            file_size=file_size,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            hash_algorithm="sha256",
            hash_digest=digest,
        )
        offer_payload = build_offer_payload(offer)
        _send_frame(sock, remote_addr, FrameType.OFFER, transfer_id, 0, offer_payload)
        accept_header, accept_payload, accept_addr = _recv_frame(sock)
        if accept_addr != remote_addr or accept_header.transfer_id != transfer_id or not is_frame_type(accept_header.frame_type, FrameType.ACCEPT):
            raise ProtocolError("invalid ACCEPT response")
        accepted, reason = parse_accept_payload(accept_payload)
        if not accepted:
            raise ProtocolError(f"receiver rejected transfer: {reason or 'no reason provided'}")

        for seq in range(total_chunks):
            chunk = data[seq * chunk_size : (seq + 1) * chunk_size]
            payload = build_data_payload(seq, chunk_size, chunk)
            acknowledged = False
            for _ in range(MAX_RETRIES):
                _send_frame(sock, remote_addr, FrameType.DATA, transfer_id, seq, payload)
                try:
                    ack_header, ack_payload, ack_addr = _recv_frame(sock)
                except TimeoutError:
                    continue
                except socket.timeout:
                    continue
                if ack_addr != remote_addr or ack_header.transfer_id != transfer_id:
                    continue
                if not is_frame_type(ack_header.frame_type, FrameType.ACK):
                    continue
                ranges = parse_ranges_payload(ack_payload)
                if any(start <= seq <= end for start, end in ranges):
                    acknowledged = True
                    break
            if not acknowledged:
                raise TimeoutError(f"chunk {seq} not acknowledged")

        fin_payload = build_fin_payload(total_chunks - 1 if total_chunks else 0, digest)
        _send_frame(sock, remote_addr, FrameType.FIN, transfer_id, 0, fin_payload)

        fin_ack_header, fin_ack_payload, fin_ack_addr = _recv_frame(sock)
        if fin_ack_addr != remote_addr or fin_ack_header.transfer_id != transfer_id or not is_frame_type(
            fin_ack_header.frame_type, FrameType.FIN_ACK
        ):
            raise ProtocolError("invalid FIN_ACK response")
        verified, receiver_digest = parse_fin_ack_payload(fin_ack_payload)
        if not verified:
            raise ProtocolError("receiver reported integrity failure")
        if receiver_digest != digest:
            raise ProtocolError("receiver digest mismatch")


def receive_one(bind_host: str, port: int, out_dir: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Path:
    destination_dir = Path(out_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_host, port))
        sock.settimeout(timeout)

        hello_header, _, sender_addr = _recv_frame(sock)
        if not is_frame_type(hello_header.frame_type, FrameType.HELLO):
            raise ProtocolError("expected HELLO")
        transfer_id = hello_header.transfer_id
        _send_frame(sock, sender_addr, FrameType.HELLO, transfer_id, 0, build_hello_payload())

        offer_header, offer_payload, offer_addr = _recv_frame(sock)
        if offer_addr != sender_addr or offer_header.transfer_id != transfer_id or not is_frame_type(offer_header.frame_type, FrameType.OFFER):
            raise ProtocolError("expected OFFER")
        offer = parse_offer_payload(offer_payload)

        _send_frame(sock, sender_addr, FrameType.ACCEPT, transfer_id, 0, build_accept_payload(True))

        output_path = destination_dir / offer.filename
        received: set[int] = set()

        with output_path.open("wb") as target:
            target.truncate(offer.file_size)

        while len(received) < offer.total_chunks:
            data_header, data_payload, data_addr = _recv_frame(sock)
            if data_addr != sender_addr or data_header.transfer_id != transfer_id:
                continue
            if not is_frame_type(data_header.frame_type, FrameType.DATA):
                continue
            seq = data_header.seq
            _, chunk = parse_data_payload(data_payload)
            if seq not in received:
                with output_path.open("r+b") as target:
                    target.seek(seq * offer.chunk_size)
                    target.write(chunk)
                received.add(seq)
            ack_payload = build_ranges_payload([(seq, seq)])
            _send_frame(sock, sender_addr, FrameType.ACK, transfer_id, seq, ack_payload)

        fin_header, fin_payload, fin_addr = _recv_frame(sock)
        if fin_addr != sender_addr or fin_header.transfer_id != transfer_id or not is_frame_type(fin_header.frame_type, FrameType.FIN):
            raise ProtocolError("expected FIN")
        _, sender_fin_digest = parse_fin_payload(fin_payload)

        file_bytes = output_path.read_bytes()
        local_digest = hashlib.sha256(file_bytes).digest()
        verified = local_digest == offer.hash_digest == sender_fin_digest
        fin_ack_payload = build_fin_ack_payload(verified, local_digest)
        _send_frame(sock, sender_addr, FrameType.FIN_ACK, transfer_id, 0, fin_ack_payload)
        if not verified:
            raise ProtocolError("integrity verification failed")

    return output_path
