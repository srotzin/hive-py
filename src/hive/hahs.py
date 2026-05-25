"""HAHS — Hire-time Anchored Hash Signature (signed receipts).

A HAHS receipt is the canonical settlement artifact for an autonomous-agent
action. It carries:

    receipt_id       a Tre'gent receipt id (TGT-<hex16>)
    symbol           the SIU (Standard Inference Unit) being settled
    units            integer units transacted
    amount_usd       integer USD cents OR float USD (issuer's choice)
    recipient        canonical recipient identifier
    issued_at        ISO 8601 UTC timestamp
    canonical_sha256 SHA-256 over JCS of all body fields above
    hahs_anchor      optional public-block anchor (e.g. Base block height)
    settlement       optional settlement instrument string

Issuance binds the body to the issuer's Ed25519 signing key. Verification
is offline, byte-match, ~50ms on commodity hardware.

HAHS is the *transparent* primitive: the receipt body is plaintext for
the auditor. For policy-hiding contexts pair with SpectralZK. For multi-
party selective reveal pair with ViewKey.
"""

from __future__ import annotations

import secrets
import datetime as _dt
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .canon import jcs, sha256, b64u, b64u_decode


PROTOCOL = "hahs/1"


def _new_receipt_id() -> str:
    return "TGT-" + secrets.token_hex(8)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_usd(amount) -> str:
    """Canonical USD format: '<int>.<2-digit fraction>'. Stable across languages."""
    if isinstance(amount, str):
        # Trust caller-provided strings unchanged.
        return amount
    return f"{float(amount):.2f}"


def issue(
    *,
    symbol: str,
    units: int,
    amount_usd,
    recipient: str,
    issuer_sk: Ed25519PrivateKey,
    receipt_id: Optional[str] = None,
    issued_at: Optional[str] = None,
    hahs_anchor: Optional[str] = None,
    settlement: Optional[str] = None,
) -> dict:
    """Issue a signed HAHS receipt.

    All body fields are folded into a canonical SHA-256 hash, which is then
    signed by the issuer. The returned dict is JSON-serializable.

    `amount_usd` is canonicalized as a decimal-formatted string with exactly
    two fractional digits so the JCS bytes match across language SDKs.
    """
    body = {
        "protocol": PROTOCOL,
        "receipt_id": receipt_id or _new_receipt_id(),
        "symbol": symbol,
        "units": int(units),
        "amount_usd": _fmt_usd(amount_usd),
        "recipient": recipient,
        "issued_at": issued_at or _now_iso(),
    }
    if hahs_anchor is not None:
        body["hahs_anchor"] = hahs_anchor
    if settlement is not None:
        body["settlement"] = settlement

    canonical_bytes = jcs(body)
    canonical_sha256 = sha256(canonical_bytes)
    signature = issuer_sk.sign(canonical_sha256)
    issuer_pubkey = issuer_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    receipt = dict(body)
    receipt["canonical_sha256"] = b64u(canonical_sha256)
    receipt["issuer_pubkey"] = "ed25519:" + b64u(issuer_pubkey)
    receipt["signature"] = "ed25519:" + b64u(signature)
    return receipt


def verify(receipt: dict, issuer_pubkey: Optional[bytes] = None) -> Tuple[bool, str]:
    """Verify a HAHS receipt.

    If `issuer_pubkey` is supplied (raw 32-byte Ed25519 pubkey or a string
    "ed25519:<b64u>"), the signature is checked against it; otherwise the
    pubkey embedded in the receipt is used. The strict pattern for high-
    assurance contexts is to pass the pubkey explicitly so a tampered
    receipt cannot bring its own pubkey.
    """
    try:
        if receipt.get("protocol") != PROTOCOL:
            return False, f"unknown protocol: {receipt.get('protocol')}"

        if isinstance(issuer_pubkey, str):
            if not issuer_pubkey.startswith("ed25519:"):
                return False, "issuer_pubkey string must be 'ed25519:<b64u>'"
            pub_bytes = b64u_decode(issuer_pubkey[len("ed25519:"):])
        elif isinstance(issuer_pubkey, (bytes, bytearray)):
            pub_bytes = bytes(issuer_pubkey)
        else:
            emb = receipt.get("issuer_pubkey", "")
            if not emb.startswith("ed25519:"):
                return False, "embedded issuer_pubkey missing or malformed"
            pub_bytes = b64u_decode(emb[len("ed25519:"):])
        if len(pub_bytes) != 32:
            return False, "Ed25519 pubkey must be 32 bytes"

        sig_field = receipt.get("signature", "")
        if not sig_field.startswith("ed25519:"):
            return False, "signature must be 'ed25519:<b64u>'"
        sig_bytes = b64u_decode(sig_field[len("ed25519:"):])
        if len(sig_bytes) != 64:
            return False, "Ed25519 signature must be 64 bytes"

        body = {k: v for k, v in receipt.items() if k not in (
            "canonical_sha256", "issuer_pubkey", "signature",
        )}
        canonical_bytes = jcs(body)
        canonical_sha256 = sha256(canonical_bytes)

        claimed = b64u_decode(receipt.get("canonical_sha256", ""))
        if claimed != canonical_sha256:
            return False, "canonical_sha256 mismatch (body was tampered)"

        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, canonical_sha256)
        except InvalidSignature:
            return False, "Ed25519 signature does not verify"

        return True, "all four checks verified"

    except Exception as e:
        return False, f"verification error: {type(e).__name__}: {e}"


__all__ = ["issue", "verify", "PROTOCOL"]
