#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sigseer — offline calldata prototype guessing & explainer (no RPC, no DB).

What it does
- analyze: Parse 0x calldata, separate selector/head/tail, find dynamic offsets.
- guess:   Infer likely ABI types per argument (address/uint/bool/bytes/string/array heads).
- name:    For well-known selectors, attach friendly names (approve, transfer, setApprovalForAll).
- output:  Pretty console, JSON report, optional SVG badge.

Examples
  $ python sigseer.py analyze 0x095ea7b3...
  $ python sigseer.py analyze data.txt --json out.json --svg badge.svg --pretty
"""

import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
from eth_utils import keccak, is_hex, to_checksum_address

KNOWN = {
    "095ea7b3": "approve(address,uint256)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "d505accf": "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)",
}

# ------------------------ helpers ------------------------

def _strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h

def _chunks(bs: bytes, n: int) -> List[bytes]:
    return [bs[i:i+n] for i in range(0, len(bs), n)]

def _u256(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

def _is_zero(b: bytes) -> bool:
    return all(x == 0 for x in b)

def _looks_address_word(w: bytes) -> bool:
    # 12 zero bytes + 20 arbitrary
    return len(w) == 32 and _is_zero(w[:12]) and not _is_zero(w[12:])

def _as_addr(w: bytes) -> str:
    return to_checksum_address("0x" + w[-20:].hex())

def _looks_bool_word(w: bytes) -> bool:
    return len(w) == 32 and _is_zero(w[:31]) and w[31] in (0,1)

def _looks_small_uint(w: bytes) -> bool:
    # Heuristic: top 30 bytes mostly zero
    return len(w) == 32 and _is_zero(w[:28])

def _is_offset_like(v: int, head_size: int, total: int) -> bool:
    return (v % 32 == 0) and (head_size <= v < total)

def _is_ascii_printable(bs: bytes) -> bool:
    if not bs: return False
    try:
        s = bs.decode("utf-8", errors="ignore")
    except Exception:
        return False
    keep = "".join(ch for ch in s if ch.isprintable())
    return len(keep) >= max(3, int(0.85 * len(s)))

def _selector(h: str) -> str:
    hh = _strip0x(h).lower()
    return hh[:8] if len(hh) >= 8 else ""

# ------------------------ data models ------------------------

@dataclass
class ArgGuess:
    index: int
    role: str           # address|uint256|bool|bytes|string|bytesN|array|unknown
    confidence: float   # 0..1
    evidence: Dict[str, Any]
    rendered: str       # human-friendly preview (address, int, len, etc.)

@dataclass
class Report:
    selector: str
    known_name: Optional[str]
    arg_guesses: List[ArgGuess]
    candidate_signatures: List[str]  # ranked textual prototypes, e.g., fn(address,uint256,bytes)
    notes: List[str]

# ------------------------ inference core ------------------------

def analyze_calldata(calldata_hex: str) -> Report:
    h = _strip0x(calldata_hex).lower()
    if len(h) < 8:
        raise click.ClickException("Calldata too short (need at least 4-byte selector).")
    sel = h[:8]
    data_hex = h[8:]
    data = bytes.fromhex(data_hex)
    words = _chunks(data, 32)
    head_size = 32 * len(words)  # abi head is same size as total words; we’ll bound offsets by total bytes
    total = len(data)

    notes: List[str] = []
    if sel in KNOWN:
        notes.append(f"Known selector match: {KNOWN[sel]}")

    # Detect dynamic pointers in head (values that look like offsets into tail)
    # Build a map idx->offset and parse pointed segments (length-prefixed).
    offsets: Dict[int, int] = {}
    for i, w in enumerate(words):
        v = _u256(w)
        if _is_offset_like(v, 0, total):
            offsets[i] = v

    # Guess static roles first
    guesses: List[ArgGuess] = []
    for i, w in enumerate(words):
        if i in offsets:
            # dynamic head
            off = offsets[i]
            if off + 32 <= total:
                ln = _u256(data[off:off+32])
                body = data[off+32: off+32+ln]
                if _is_ascii_printable(body):
                    role, conf = "string", 0.85
                else:
                    role, conf = "bytes", 0.8
                rendered = f"len={ln}"
                guesses.append(ArgGuess(i, role, conf, {"offset": off, "len": ln}, rendered))
            else:
                guesses.append(ArgGuess(i, "bytes", 0.4, {"offset": off, "warn":"out_of_bounds"}, "len=?"))
        else:
            if _looks_address_word(w):
                guesses.append(ArgGuess(i, "address", 0.98, {"pattern":"12_zero_pad"}, _as_addr(w)))
            elif _looks_bool_word(w):
                guesses.append(ArgGuess(i, "bool", 0.95, {}, bool(w[31])))
            elif _looks_small_uint(w):
                val = _u256(w)
                guesses.append(ArgGuess(i, "uint256", 0.8, {"small": True}, val))
            else:
                # Unknown static; default to uint256
                val = _u256(w)
                guesses.append(ArgGuess(i, "uint256", 0.6, {"raw": True}, val))

    # Build candidate signatures (rank: static address/uint/bool first, then dynamic types)
    order = [g.role for g in guesses]
    # compress bytes vs string names but keep order
    proto = ",".join("address" if r=="address" else
                     "bool" if r=="bool" else
                     "string" if r=="string" else
                     "bytes" if r=="bytes" else
                     "uint256" for r in order)
    candidates = []
    if sel in KNOWN:
        candidates.append(KNOWN[sel])
    # Add an anonymous prototype
    candidates.append(f"fn({proto})")
    # Heuristic alternative: if last arg is bytes but printable, prefer string
    if guesses and guesses[-1].role == "bytes" and guesses[-1].confidence >= 0.8:
        alt = ",".join(order[:-1] + ["string"])
        candidates.append(f"fn({alt})")

    return Report(selector=sel, known_name=KNOWN.get(sel), arg_guesses=guesses, candidate_signatures=candidates, notes=notes)

# ------------------------ CLI ------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """sigseer — calldata prototype guessing & explainer (offline)."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write SVG badge.")
@click.option("--pretty", is_flag=True, help="Human-readable console output.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    """
    Analyze a single 0x-calldata, or a text file with multiple lines, or '-' for stdin.
    """
    lines: List[str] = []
    if input_arg == "-":
        lines = [l.strip() for l in sys.stdin if l.strip()]
    elif os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    else:
        lines = [input_arg]

    reports: List[Report] = []
    for ln in lines:
        if not ln.startswith("0x"):
            reports.append(Report(selector="", known_name=None, arg_guesses=[], candidate_signatures=[], notes=[f"Line ignored (not 0x…): {ln[:32]}…"]))
            continue
        try:
            rep = analyze_calldata(ln)
            reports.append(rep)
        except click.ClickException as e:
            reports.append(Report(selector="", known_name=None, arg_guesses=[], candidate_signatures=[], notes=[f"Parse error: {e}"]))

    if pretty:
        for r in reports:
            if not r.selector:
                click.echo(f"[skip] {r.notes[0]}")
                continue
            tag = r.known_name or "unknown"
            click.echo(f"[{r.selector}] {tag}")
            for g in r.arg_guesses:
                click.echo(f"  arg{g.index}: {g.role:<8} conf={g.confidence:.2f}  {g.rendered}")
            if r.candidate_signatures:
                click.echo("  candidates:")
                for c in r.candidate_signatures[:3]:
                    click.echo(f"    - {c}")
            if r.notes:
                click.echo("  notes: " + "; ".join(r.notes))

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "selector": r.selector,
                "known_name": r.known_name,
                "arg_guesses": [asdict(g) for g in r.arg_guesses],
                "candidate_signatures": r.candidate_signatures,
                "notes": r.notes
            } for r in reports], f, indent=2)
        click.echo(f"Wrote JSON: {json_out}")

    if svg_out:
        # Show the first line’s status
        r = next((x for x in reports if x.selector), None)
        if r is None:
            click.echo("No valid calldata for SVG.")
        else:
            color = "#3fb950" if r.known_name else "#d29922"
            title = r.known_name or f"fn({','.join([g.role for g in r.arg_guesses])})"
            svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="620" height="48" role="img" aria-label="sigseer">
  <rect width="620" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    sigseer: {r.selector} → {title}
  </text>
  <circle cx="595" cy="24" r="6" fill="{color}"/>
</svg>"""
            with open(svg_out, "w", encoding="utf-8") as f:
                f.write(svg)
            click.echo(f"Wrote SVG: {svg_out}")

    if not (pretty or json_out or svg_out):
        # default: print JSON to stdout
        print(json.dumps([{
            "selector": r.selector,
            "known_name": r.known_name,
            "arg_guesses": [asdict(g) for g in r.arg_guesses],
            "candidate_signatures": r.candidate_signatures,
            "notes": r.notes
        } for r in reports], indent=2))

if __name__ == "__main__":
    cli()
