"""
Hive CLI — `hive` command entry point.
Hive Civilization · src/hive/cli.py

Subcommands:
  hive verify <file.json>          Auto-detect protocol and verify
  hive prove-sample <out.json>     Generate a SpectralZK sample proof
  hive issue --actor X --action Y --amount Z --counterparty W
                                    Issue a HAHS receipt with an ephemeral key
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from . import hahs, spectralzk


def _detect_protocol(doc: dict) -> str:
    p = doc.get("protocol", "")
    if p.startswith("hahs/"):
        return "hahs"
    if p.startswith("spectralzk/"):
        return "spectralzk"
    return ""


def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.file, "r", encoding="utf-8") as f:
        doc = json.load(f)
    kind = _detect_protocol(doc)
    if kind == "hahs":
        ok, reason = hahs.verify(doc)
    elif kind == "spectralzk":
        ok, reason = spectralzk.verify(doc)
    else:
        print(f"  RESULT:  FAIL", file=sys.stderr)
        print(f"  reason:  unknown or missing protocol field", file=sys.stderr)
        return 2

    print()
    if ok:
        print("  RESULT:    PASS")
        print(f"  protocol:  {doc.get('protocol')}")
        print(f"  reason:    {reason}")
        print("  verified offline. no network contacted.")
        print()
        return 0
    print("  RESULT:    FAIL")
    print(f"  protocol:  {doc.get('protocol')}")
    print(f"  reason:    {reason}")
    print()
    return 1


def cmd_prove_sample(args: argparse.Namespace) -> int:
    seed = b"hive-spectralzk-v1-sample-issuer-seed-2026-05"
    sk_bytes = hashlib.sha256(seed).digest()
    issuer_sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    constraints = [
        spectralzk.Constraint("spend_usd_per_day", 0, 50, b"\x01" * 16),
        spectralzk.Constraint("spend_usd_per_day", 51, 200, b"\x02" * 16),
        spectralzk.Constraint("spend_usd_per_day", 201, 1000, b"\x03" * 16),
        spectralzk.Constraint("spend_usd_per_day", 1001, 10000, b"\x04" * 16),
    ]
    action = spectralzk.Action(attr="spend_usd_per_day", value=145)
    proof = spectralzk.prove(issuer_sk, "hive.policy.shod.spend-tier.v1", constraints, action)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(proof, f, indent=2, ensure_ascii=False)
    print(f"sample proof written to {args.out}")
    print(f"issuer pubkey: {proof['issuer_pubkey']}")
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    sk = Ed25519PrivateKey.generate()
    receipt = hahs.issue(
        symbol=args.symbol,
        units=args.units,
        amount_usd=args.amount,
        recipient=args.recipient,
        issuer_sk=sk,
        hahs_anchor=args.hahs_anchor,
        settlement=args.settlement,
    )
    out = args.out or "-"
    text = json.dumps(receipt, indent=2, ensure_ascii=False)
    if out == "-":
        print(text)
    else:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"receipt written to {out}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hive", description="Hive Protocol CLI")
    p.add_argument("--version", action="version", version=f"hive {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("verify", help="Verify a HAHS or SpectralZK document")
    pv.add_argument("file")
    pv.set_defaults(func=cmd_verify)

    pps = sub.add_parser("prove-sample", help="Generate a SpectralZK sample proof")
    pps.add_argument("out")
    pps.set_defaults(func=cmd_prove_sample)

    pi = sub.add_parser("issue", help="Issue a HAHS receipt with an ephemeral key")
    pi.add_argument("--symbol", required=True, help="SIU symbol (e.g. INF.GPT-4)")
    pi.add_argument("--units", required=True, type=int)
    pi.add_argument("--amount", required=True, type=float, help="Amount in USD")
    pi.add_argument("--recipient", required=True)
    pi.add_argument("--hahs-anchor", default=None)
    pi.add_argument("--settlement", default=None)
    pi.add_argument("--out", default="-")
    pi.set_defaults(func=cmd_issue)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
