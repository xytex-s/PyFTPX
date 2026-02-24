# PyFTPX

PyFTPX is a **Python File Transfer eXperimental Protocol** project.

Current focus: define a robust, UDP-first protocol before implementation.

## Project Structure

- `docs/protocol-spec.md` — full protocol specification (v0.1 draft)
- `src/pyftpx/` — protocol implementation package
- `tests/` — protocol and integration test suite
- `scripts/smoke_test.ps1` — one-command local sender/receiver verification
- `src/pyftpx/smoke_test.py` — cross-shell Python smoke test module

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

## Smoke Test (Windows PowerShell)

Run this from the repo root:

```powershell
.\scripts\smoke_test.ps1
```

Optional parameters:

```powershell
.\scripts\smoke_test.ps1 -Port 40404 -ReceiverTimeoutSec 30 -SenderTimeoutSec 10
```

The script starts a local receiver, sends `sample.txt`, and verifies SHA256 hashes match.

## Smoke Test (Python Module)

Run this from the repo root:

```powershell
$env:PYTHONPATH='src'; .\.venv\Scripts\python.exe -m pyftpx.smoke_test
```

This runs the same local sender/receiver test path and verifies file hash integrity.
