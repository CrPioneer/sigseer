# sigseer — see what your calldata is trying to say

**sigseer** is a zero-RPC, offline CLI that takes Ethereum calldata (0x…) and
**guesses the function prototype** without using any online signatures database.
It inspects ABI layout, detects dynamic pointers, and infers types with clear,
human-readable reasoning.

## Why this is useful

- Phishing sites and strange UIs often show a 0x “Data” blob.
- Etherscan sometimes lacks a verified ABI.
- You just want a **fast, offline** sense of “is this `(address,uint256)` or is it sneaking a `bytes` payload?”

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
