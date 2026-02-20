# PyFTPX Protocol Specification

Version: `0.1-draft`  
Status: Draft  
Transport: UDP (IPv4/IPv6)

---

## 1. Design Objectives

PyFTPX defines a reliable file transfer protocol over UDP with:

1. Ordered or sparse chunk delivery
2. Explicit acknowledgements and retransmissions
3. File integrity verification
4. Transfer resumption support (phase 2)
5. Extension hooks for encryption/compression

Non-goals for v0.1:

- Multi-stream multiplexing in one session
- NAT traversal mechanisms
- Built-in PKI trust model

---

## 2. Terminology

- **Session**: One logical transfer exchange between sender and receiver.
- **Transfer ID (`tid`)**: 64-bit random identifier for a transfer.
- **Chunk**: File byte segment carried in a `DATA` frame.
- **Sequence (`seq`)**: 32-bit chunk sequence number.
- **Window**: Max in-flight unacknowledged chunks.

---

## 3. Transport and Ports

- Default UDP port: `40404`
- One transfer per `tid`
- Receiver may host multiple concurrent transfers (distinct `tid`)
- Maximum datagram size target: `<= 1200` bytes payload+header (safe baseline for internet MTU)

---

## 4. Wire Format

All multibyte integers are **big-endian**.

### 4.1 Common Header (24 bytes)

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| 0 | 4 | Magic | bytes | ASCII `PFXP` |
| 4 | 1 | Version | u8 | Protocol version (`1`) |
| 5 | 1 | Type | u8 | Frame type |
| 6 | 1 | Flags | u8 | Type-specific flags |
| 7 | 1 | HeaderLen | u8 | Header bytes including common header |
| 8 | 8 | TransferID | u64 | Session transfer identifier |
| 16 | 4 | Seq | u32 | Sequence number (or 0 if unused) |
| 20 | 4 | PayloadLen | u32 | Payload bytes after header |

`HeaderLen` enables optional type-specific extension fields.

### 4.2 Frame Types

| Value | Name | Purpose |
|---:|---|---|
| 0x01 | `HELLO` | Capability announcement / negotiation start |
| 0x02 | `OFFER` | Sender file metadata offer |
| 0x03 | `ACCEPT` | Receiver accept/reject offer |
| 0x04 | `DATA` | File chunk payload |
| 0x05 | `ACK` | Positive acknowledgement / ranges |
| 0x06 | `NACK` | Negative acknowledgement / missing ranges |
| 0x07 | `FIN` | Sender transfer completion marker |
| 0x08 | `FIN_ACK` | Receiver completion confirmation |
| 0x09 | `ABORT` | Immediate transfer termination |
| 0x0A | `PING` | Keepalive/RTT sampling |
| 0x0B | `PONG` | Keepalive reply |

---

## 5. Frame Payload Definitions

Payload encoding uses TLV unless specified. TLV format:

- `tag`: `u8`
- `len`: `u16`
- `value`: `len` bytes

### 5.1 HELLO

Purpose: identify peer capabilities.

Required TLVs:

- `0x01`: implementation name (UTF-8)
- `0x02`: implementation version (UTF-8)
- `0x03`: max datagram size (`u16`)
- `0x04`: supported hash list (CSV UTF-8; e.g., `sha256,blake2b`)

Optional TLVs:

- `0x10`: supported compression list
- `0x11`: supported encryption suites

### 5.2 OFFER

Sender proposes file transfer.

Required TLVs:

- `0x01`: file name (UTF-8, basename only)
- `0x02`: file size (`u64`)
- `0x03`: chunk size (`u16`)
- `0x04`: total chunks (`u32`)
- `0x05`: file hash algorithm (UTF-8)
- `0x06`: file hash digest (raw bytes)

Optional TLVs:

- `0x20`: relative path hint (UTF-8)
- `0x21`: mtime unix seconds (`u64`)

### 5.3 ACCEPT

Receiver response to `OFFER`.

Required TLVs:

- `0x01`: decision (`u8`) — `1=accept`, `0=reject`

Optional TLVs:

- `0x02`: reason (UTF-8)
- `0x03`: resume bitmap/range support indicator (`u8`)

### 5.4 DATA

`seq` identifies chunk index starting at `0`.

Payload:

- 4 bytes: `offset_low32` (for integrity check convenience)
- N bytes: chunk data

`offset = seq * chunk_size` is authoritative in v0.1.

### 5.5 ACK / NACK

Use payload range list:

- 2 bytes: range count `k`
- Then `k` records:
  - `start_seq` (`u32`)
  - `end_seq` (`u32`, inclusive)

For `ACK`: ranges successfully received.
For `NACK`: ranges currently missing and desired.

### 5.6 FIN

Required TLVs:

- `0x01`: last seq sent (`u32`)
- `0x02`: sender computed hash digest (raw bytes)

### 5.7 FIN_ACK

Required TLVs:

- `0x01`: status (`u8`) — `1=verified`, `0=verification_failed`
- `0x02`: receiver hash digest (raw bytes)

### 5.8 ABORT

Required TLVs:

- `0x01`: code (`u16`)
- `0x02`: message (UTF-8)

Abort codes:

- `1001`: protocol error
- `1002`: unsupported capability
- `1003`: local I/O failure
- `1004`: integrity failure
- `1005`: timeout

---

## 6. Session State Machines

### 6.1 Sender

`IDLE -> HELLO_SENT -> OFFER_SENT -> TRANSFERRING -> FIN_SENT -> DONE`

Transitions:

- Send `HELLO`; await peer `HELLO`
- Send `OFFER`; await `ACCEPT(decision=1)`
- Stream `DATA` under congestion/window rules
- Retransmit on `NACK` or timeout
- Send `FIN` after all chunks ACKed
- Wait `FIN_ACK(status=1)` then complete

Failure transitions:

- Any fatal parse/protocol violation: send `ABORT`, close
- Retry budget exhausted: send `ABORT(code=1005)`

### 6.2 Receiver

`IDLE -> HELLO_EXCHANGED -> OFFER_RECEIVED -> RECEIVING -> VERIFYING -> DONE`

Transitions:

- Receive peer `HELLO`, reply `HELLO`
- Validate `OFFER`, send `ACCEPT`
- Write chunks by `seq`; deduplicate repeated chunks
- Emit periodic `ACK` and targeted `NACK`
- On `FIN`, verify full file hash
- Send `FIN_ACK(status=1|0)`

---

## 7. Reliability and Flow Control

### 7.1 Sliding Window

- Configurable window size in chunks (default: `64`)
- Sender may send new `DATA` only when in-flight < window

### 7.2 Retransmission Timer (RTO)

- Initial RTO: `500 ms`
- RTT sampled via `PING/PONG` or ACK turnaround
- RTO bounds: `200 ms` min, `5 s` max
- Exponential backoff on repeated timeout for same `seq`

### 7.3 ACK Policy

Receiver sends ACK:

- Every `N` chunks received (`N=16` default), or
- Every `100 ms` flush timer, whichever first

Receiver sends NACK when gaps persist for > `150 ms`.

---

## 8. Integrity and Security

### 8.1 Integrity

- Mandatory file hash in `OFFER` and `FIN`
- Receiver must recompute and compare
- Any mismatch => `FIN_ACK(status=0)` and optional `ABORT(1004)`

### 8.2 Security (v0.1 baseline)

- No mandatory encryption in core v0.1
- Extension point via `HELLO` capabilities for authenticated encryption mode
- Implementations should support local policy: allowlist peers, max file size, destination sandbox directory

---

## 9. Error Handling Rules

A peer MUST send `ABORT` and terminate session on:

1. Invalid magic/version
2. Declared payload length mismatch
3. Malformed TLV in required fields
4. Unexpected frame type for current state

A peer SHOULD ignore duplicate `DATA` for already committed `seq` and ACK as needed.

---

## 10. Resume Semantics (Phase 2)

Reserved for next milestone:

- Receiver advertises resume support in `ACCEPT`
- Sender can request sparse ACK map on reconnect using same file identity hash
- Recovered transfer continues with missing sequences only

---

## 11. Versioning and Compatibility

- `Version=1` for this draft
- Unknown optional TLVs must be ignored
- Unknown required semantics should trigger `ABORT(1002)`

---

## 12. Implementation Milestones

### Milestone A: Core Transfer

- HELLO/OFFER/ACCEPT/DATA/ACK/FIN/FIN_ACK
- Single file transfer, no resume

### Milestone B: Robustness

- NACK-based gap repair
- Adaptive RTO
- Fault injection test harness

### Milestone C: Extensions

- Resume support
- Compression negotiation
- Authenticated encryption profile
