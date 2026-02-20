# PyFTPX

PyFTPX is a **Python File Transfer eXperimental Protocol** project.

Current focus: define a robust, UDP-first protocol before implementation.

## Project Structure

- `docs/protocol-spec.md` — full protocol specification (v0.1 draft)
- `src/pyftpx/` — protocol implementation package (to be built)
- `tests/` — protocol and integration test suite (to be built)

## Goals

- Reliable file transfer over UDP
- Chunking, ordering, and retransmission strategy
- Integrity verification with file hashing
- Resumable transfers (planned in phased implementation)
- Extensible capability negotiation (compression/encryption)

## Next Steps

1. Implement packet encoder/decoder from the spec.
2. Implement sender/receiver state machines.
3. Add loss/latency simulation tests.
4. Add CLI for send/receive operations.
