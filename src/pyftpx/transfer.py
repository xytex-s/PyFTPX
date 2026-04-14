from __future__ import annotations

import hashlib
import random
import socket
import time
from enum import Enum
from pathlib import Path

from .codec import decode_frame
from .codec import encode_frame
from .protocol import Offer
from .protocol import build_accept_payload
from .protocol import build_abort_payload
from .protocol import build_data_payload
from .protocol import build_fin_ack_payload
from .protocol import build_fin_payload
from .protocol import build_hello_payload
from .protocol import build_offer_payload
from .protocol import build_ranges_payload
from .protocol import is_frame_type
from .protocol import parse_accept_payload
from .protocol import parse_abort_payload
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


class SenderState(str, Enum):
    IDLE = "IDLE"
    HELLO_SENT = "HELLO_SENT"
    OFFER_SENT = "OFFER_SENT"
    TRANSFERRING = "TRANSFERRING"
    FIN_SENT = "FIN_SENT"
    DONE = "DONE"


class ReceiverState(str, Enum):
    IDLE = "IDLE"
    HELLO_EXCHANGED = "HELLO_EXCHANGED"
    OFFER_RECEIVED = "OFFER_RECEIVED"
    RECEIVING = "RECEIVING"
    VERIFYING = "VERIFYING"
    DONE = "DONE"


ACK_EVERY_CHUNKS = 16
ACK_FLUSH_INTERVAL = 0.1
NACK_GAP_SECONDS = 0.15
WINDOW_SIZE = 64
INITIAL_RTO_SECONDS = 0.5
MIN_RTO_SECONDS = 0.2
MAX_RTO_SECONDS = 5.0


def _ranges_from_set(values: set[int]) -> list[tuple[int, int]]:
    if not values:
        return []
    out: list[tuple[int, int]] = []
    for seq in sorted(values):
        if not out or seq != out[-1][1] + 1:
            out.append((seq, seq))
        else:
            out[-1] = (out[-1][0], seq)
    return out


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


def _raise_peer_abort(payload: bytes) -> None:
    code, message = parse_abort_payload(payload)
    raise ProtocolError(f"peer aborted transfer ({code}): {message or 'no message'}")


def _send_abort(sock: socket.socket, addr: tuple[str, int], transfer_id: int, code: int, message: str) -> None:
    _send_frame(sock, addr, FrameType.ABORT, transfer_id, 0, build_abort_payload(code, message))


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
    state = SenderState.IDLE

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)

        hello_payload = build_hello_payload()
        _send_frame(sock, remote_addr, FrameType.HELLO, transfer_id, 0, hello_payload)
        state = SenderState.HELLO_SENT
        hello_header, hello_response_payload, hello_addr = _recv_frame(sock)
        if hello_addr != remote_addr or hello_header.transfer_id != transfer_id:
            raise ProtocolError("invalid HELLO response")
        if is_frame_type(hello_header.frame_type, FrameType.ABORT):
            _raise_peer_abort(hello_response_payload)
        if not is_frame_type(hello_header.frame_type, FrameType.HELLO):
            _send_abort(sock, remote_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
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
        state = SenderState.OFFER_SENT
        accept_header, accept_payload, accept_addr = _recv_frame(sock)
        if accept_addr != remote_addr or accept_header.transfer_id != transfer_id:
            raise ProtocolError("invalid ACCEPT response")
        if is_frame_type(accept_header.frame_type, FrameType.ABORT):
            _raise_peer_abort(accept_payload)
        if not is_frame_type(accept_header.frame_type, FrameType.ACCEPT):
            _send_abort(sock, remote_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
            raise ProtocolError("invalid ACCEPT response")
        accepted, reason = parse_accept_payload(accept_payload)
        if not accepted:
            raise ProtocolError(f"receiver rejected transfer: {reason or 'no reason provided'}")

        state = SenderState.TRANSFERRING
        in_flight: dict[int, dict[str, float | int]] = {}
        acked: set[int] = set()
        next_seq = 0
        srtt: float | None = None
        rttvar: float | None = None
        rto = INITIAL_RTO_SECONDS

        def update_rto(sample_rtt: float) -> None:
            nonlocal srtt, rttvar, rto
            alpha = 1.0 / 8.0
            beta = 1.0 / 4.0
            if srtt is None or rttvar is None:
                srtt = sample_rtt
                rttvar = sample_rtt / 2.0
            else:
                rttvar = (1.0 - beta) * rttvar + beta * abs(srtt - sample_rtt)
                srtt = (1.0 - alpha) * srtt + alpha * sample_rtt
            rto = srtt + max(0.01, 4.0 * rttvar)
            rto = max(MIN_RTO_SECONDS, min(MAX_RTO_SECONDS, rto))

        while len(acked) < total_chunks:
            while next_seq < total_chunks and len(in_flight) < WINDOW_SIZE:
                chunk = data[next_seq * chunk_size : (next_seq + 1) * chunk_size]
                payload = build_data_payload(next_seq, chunk_size, chunk)
                _send_frame(sock, remote_addr, FrameType.DATA, transfer_id, next_seq, payload)
                in_flight[next_seq] = {"sent": time.monotonic(), "retries": 0}
                next_seq += 1

            now = time.monotonic()
            if in_flight:
                next_deadline = min(info["sent"] + rto for info in in_flight.values())
                sock.settimeout(max(0.0, min(ACK_FLUSH_INTERVAL, next_deadline - now)))
            else:
                sock.settimeout(ACK_FLUSH_INTERVAL)

            try:
                ack_header, ack_payload, ack_addr = _recv_frame(sock)
            except (TimeoutError, socket.timeout, BlockingIOError):
                ack_header = None
                ack_payload = b""
                ack_addr = ("", 0)

            if ack_header is not None:
                if ack_addr != remote_addr or ack_header.transfer_id != transfer_id:
                    continue
                if is_frame_type(ack_header.frame_type, FrameType.ABORT):
                    _raise_peer_abort(ack_payload)
                if is_frame_type(ack_header.frame_type, FrameType.ACK):
                    ranges = parse_ranges_payload(ack_payload)
                    for start, end in ranges:
                        for seq in range(start, end + 1):
                            if seq in acked:
                                continue
                            acked.add(seq)
                            if seq in in_flight:
                                info = in_flight.pop(seq)
                                sample = time.monotonic() - float(info["sent"])
                                update_rto(sample)
                    continue
                if is_frame_type(ack_header.frame_type, FrameType.NACK):
                    missing_ranges = parse_ranges_payload(ack_payload)
                    for start, end in missing_ranges:
                        for seq in range(start, end + 1):
                            if seq in acked or seq >= total_chunks:
                                continue
                            if seq >= next_seq:
                                continue
                            info = in_flight.get(seq)
                            if info is None:
                                continue
                            if int(info["retries"]) >= MAX_RETRIES:
                                _send_abort(sock, remote_addr, transfer_id, 1005, f"chunk {seq} not acknowledged")
                                raise TimeoutError(f"chunk {seq} not acknowledged")
                            chunk = data[seq * chunk_size : (seq + 1) * chunk_size]
                            payload = build_data_payload(seq, chunk_size, chunk)
                            _send_frame(sock, remote_addr, FrameType.DATA, transfer_id, seq, payload)
                            info["sent"] = time.monotonic()
                            info["retries"] = int(info["retries"]) + 1
                    continue
                _send_abort(sock, remote_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
                raise ProtocolError("unexpected frame during data transfer")

            now = time.monotonic()
            for seq, info in list(in_flight.items()):
                if now - float(info["sent"]) < rto:
                    continue
                retries = int(info["retries"]) + 1
                if retries > MAX_RETRIES:
                    _send_abort(sock, remote_addr, transfer_id, 1005, f"chunk {seq} not acknowledged")
                    raise TimeoutError(f"chunk {seq} not acknowledged")
                chunk = data[seq * chunk_size : (seq + 1) * chunk_size]
                payload = build_data_payload(seq, chunk_size, chunk)
                _send_frame(sock, remote_addr, FrameType.DATA, transfer_id, seq, payload)
                info["sent"] = now
                info["retries"] = retries
                rto = min(MAX_RTO_SECONDS, rto * 2.0)

        fin_payload = build_fin_payload(total_chunks - 1 if total_chunks else 0, digest)
        _send_frame(sock, remote_addr, FrameType.FIN, transfer_id, 0, fin_payload)
        state = SenderState.FIN_SENT
        sock.settimeout(timeout)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("FIN_ACK not received")
            sock.settimeout(remaining)
            try:
                fin_ack_header, fin_ack_payload, fin_ack_addr = _recv_frame(sock)
            except ConnectionResetError:
                continue
            if fin_ack_addr != remote_addr or fin_ack_header.transfer_id != transfer_id:
                continue
            if is_frame_type(fin_ack_header.frame_type, FrameType.ABORT):
                _raise_peer_abort(fin_ack_payload)
            if not is_frame_type(fin_ack_header.frame_type, FrameType.FIN_ACK):
                _send_abort(sock, remote_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
                raise ProtocolError("invalid FIN_ACK response")
            verified, receiver_digest = parse_fin_ack_payload(fin_ack_payload)
            if not verified:
                raise ProtocolError("receiver reported integrity failure")
            if receiver_digest != digest:
                raise ProtocolError("receiver digest mismatch")
            break
        state = SenderState.DONE


def receive_one(bind_host: str, port: int, out_dir: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Path:
    destination_dir = Path(out_dir)
    destination_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((bind_host, port))
        sock.settimeout(timeout)
        state = ReceiverState.IDLE

        hello_header, _, sender_addr = _recv_frame(sock)
        if not is_frame_type(hello_header.frame_type, FrameType.HELLO):
            _send_abort(sock, sender_addr, hello_header.transfer_id, 1001, "expected HELLO")
            raise ProtocolError("expected HELLO")
        transfer_id = hello_header.transfer_id
        _send_frame(sock, sender_addr, FrameType.HELLO, transfer_id, 0, build_hello_payload())
        state = ReceiverState.HELLO_EXCHANGED

        offer_header, offer_payload, offer_addr = _recv_frame(sock)
        if offer_addr != sender_addr or offer_header.transfer_id != transfer_id:
            raise ProtocolError("expected OFFER")
        if is_frame_type(offer_header.frame_type, FrameType.ABORT):
            _raise_peer_abort(offer_payload)
        if not is_frame_type(offer_header.frame_type, FrameType.OFFER):
            _send_abort(sock, sender_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
            raise ProtocolError("expected OFFER")
        try:
            offer = parse_offer_payload(offer_payload)
        except ProtocolError:
            _send_abort(sock, sender_addr, transfer_id, 1001, "malformed OFFER payload")
            raise
        state = ReceiverState.OFFER_RECEIVED

        _send_frame(sock, sender_addr, FrameType.ACCEPT, transfer_id, 0, build_accept_payload(True))
        state = ReceiverState.RECEIVING

        output_path = destination_dir / offer.filename
        received: set[int] = set()
        missing_since: dict[int, float] = {}
        max_seen = -1
        last_ack_time = time.monotonic()
        last_nack_time = time.monotonic()
        new_since_ack = 0

        with output_path.open("wb") as target:
            target.truncate(offer.file_size)

        while len(received) < offer.total_chunks:
            try:
                data_header, data_payload, data_addr = _recv_frame(sock)
            except (TimeoutError, socket.timeout):
                data_header = None
                data_payload = b""
                data_addr = ("", 0)

            now = time.monotonic()
            if data_header is not None:
                if data_addr != sender_addr or data_header.transfer_id != transfer_id:
                    continue
                if is_frame_type(data_header.frame_type, FrameType.ABORT):
                    _raise_peer_abort(data_payload)
                if not is_frame_type(data_header.frame_type, FrameType.DATA):
                    _send_abort(sock, sender_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
                    raise ProtocolError("unexpected frame while receiving data")
                seq = data_header.seq
                _, chunk = parse_data_payload(data_payload)
                if seq not in received:
                    with output_path.open("r+b") as target:
                        target.seek(seq * offer.chunk_size)
                        target.write(chunk)
                    received.add(seq)
                    new_since_ack += 1
                if seq > max_seen:
                    for missing_seq in range(max_seen + 1, seq):
                        if missing_seq not in received:
                            missing_since.setdefault(missing_seq, now)
                    max_seen = seq
                if seq in missing_since:
                    del missing_since[seq]

            if new_since_ack >= ACK_EVERY_CHUNKS or now - last_ack_time >= ACK_FLUSH_INTERVAL:
                ack_payload = build_ranges_payload(_ranges_from_set(received))
                _send_frame(sock, sender_addr, FrameType.ACK, transfer_id, 0, ack_payload)
                last_ack_time = now
                new_since_ack = 0

            if now - last_nack_time >= ACK_FLUSH_INTERVAL and missing_since:
                overdue = {seq for seq, since in missing_since.items() if now - since >= NACK_GAP_SECONDS}
                if overdue:
                    nack_payload = build_ranges_payload(_ranges_from_set(overdue))
                    _send_frame(sock, sender_addr, FrameType.NACK, transfer_id, 0, nack_payload)
                    last_nack_time = now

        state = ReceiverState.VERIFYING
        while True:
            fin_header, fin_payload, fin_addr = _recv_frame(sock)
            if fin_addr != sender_addr or fin_header.transfer_id != transfer_id:
                continue
            if is_frame_type(fin_header.frame_type, FrameType.ABORT):
                _raise_peer_abort(fin_payload)
            if is_frame_type(fin_header.frame_type, FrameType.DATA):
                ack_payload = build_ranges_payload(_ranges_from_set(received))
                _send_frame(sock, sender_addr, FrameType.ACK, transfer_id, 0, ack_payload)
                continue
            if not is_frame_type(fin_header.frame_type, FrameType.FIN):
                _send_abort(sock, sender_addr, transfer_id, 1001, f"unexpected frame in {state.value}")
                raise ProtocolError("expected FIN")
            break
        _, sender_fin_digest = parse_fin_payload(fin_payload)

        file_bytes = output_path.read_bytes()
        local_digest = hashlib.sha256(file_bytes).digest()
        verified = local_digest == offer.hash_digest == sender_fin_digest
        fin_ack_payload = build_fin_ack_payload(verified, local_digest)
        _send_frame(sock, sender_addr, FrameType.FIN_ACK, transfer_id, 0, fin_ack_payload)
        if not verified:
            _send_abort(sock, sender_addr, transfer_id, 1004, "integrity verification failed")
            raise ProtocolError("integrity verification failed")
        state = ReceiverState.DONE

    return output_path
