"""
ViewKey — selective disclosure lenses for HAHS receipts.
Hive Civilization · src/hive/viewkey.py

A ViewKey is a deterministic projection of a HAHS receipt (or SHOD/SpectralZK
artifact) into a subset of fields tailored to a particular audience:

  - HOLDER       — full receipt (the agent operator)
  - REGULATOR    — actor identity, action, policy commitment, signature, but
                   strips counterparty PII and free-form metadata
  - COUNTERPARTY — proves "this payment came from a Hive-signed agent under
                   policy X" without revealing the operator's policy contents
                   or other receipts in the same period

The lens is enforced by a HMAC tag bound to (receipt_canonical_hash, audience,
field_set) using a 32-byte audience key. The receiver verifies the tag against
the canonical hash they recompute over the disclosed fields, so a holder cannot
silently add or remove a field without breaking the tag.

This is NOT encryption. The lens decides what fields ship over the wire; the
HMAC binds that decision to the audience so it cannot be tampered downstream.
For encrypted lenses, wrap the lensed receipt in a JWE or NaCl box.
"""

from __future__ import annotations

import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .canon import b64u, b64u_decode, canonical_hash, jcs

PROTOCOL = "viewkey/1"

AUDIENCE_HOLDER = "holder"
AUDIENCE_REGULATOR = "regulator"
AUDIENCE_COUNTERPARTY = "counterparty"

# Default field sets per audience. Callers can override.
DEFAULT_FIELDS: Dict[str, List[str]] = {
    AUDIENCE_HOLDER: [
        "protocol", "receipt_id", "issued_at", "symbol", "units",
        "amount_usd", "recipient", "hahs_anchor", "settlement",
        "canonical_sha256", "issuer_pubkey", "signature",
    ],
    AUDIENCE_REGULATOR: [
        "protocol", "receipt_id", "issued_at", "symbol", "units",
        "amount_usd", "canonical_sha256", "issuer_pubkey", "signature",
    ],
    AUDIENCE_COUNTERPARTY: [
        "protocol", "receipt_id", "issued_at", "symbol", "units",
        "amount_usd", "recipient", "canonical_sha256",
        "issuer_pubkey", "signature",
    ],
}


@dataclass
class ViewKey:
    """A symmetric audience key. 32 random bytes."""
    audience: str
    key: bytes

    def to_b64u(self) -> str:
        return f"vk:{self.audience}:" + b64u(self.key)

    @classmethod
    def generate(cls, audience: str) -> "ViewKey":
        return cls(audience=audience, key=secrets.token_bytes(32))

    @classmethod
    def from_b64u(cls, s: str) -> "ViewKey":
        if not s.startswith("vk:"):
            raise ValueError("ViewKey must start with 'vk:'")
        _, audience, key_b64 = s.split(":", 2)
        return cls(audience=audience, key=b64u_decode(key_b64))


def _project(receipt: dict, fields: List[str]) -> dict:
    out = {}
    for f in fields:
        if f in receipt:
            out[f] = receipt[f]
    return out


def lens(
    receipt: dict,
    vk: ViewKey,
    fields: Optional[List[str]] = None,
) -> dict:
    """Project a receipt through the given ViewKey.

    Returns a new dict with:
      - the projected fields
      - viewkey.audience
      - viewkey.fields (the field set the holder claims to have disclosed)
      - viewkey.original_hash (canonical hash of the full input receipt)
      - viewkey.tag (HMAC-SHA256 over the canonical hash of the projection)

    The receiver re-canonicalizes the projected fields, recomputes the tag
    against their copy of the audience key, and rejects on mismatch.
    """
    field_list = fields or DEFAULT_FIELDS.get(vk.audience)
    if field_list is None:
        raise ValueError(f"no default field set for audience '{vk.audience}'")

    projection = _project(receipt, field_list)
    original_hash = canonical_hash(receipt)
    projection_hash = canonical_hash(projection)

    tag_input = jcs({
        "protocol": PROTOCOL,
        "audience": vk.audience,
        "fields": field_list,
        "original_hash": b64u(original_hash),
        "projection_hash": b64u(projection_hash),
    })
    tag = hmac.new(vk.key, tag_input, hashlib.sha256).digest()

    out = dict(projection)
    out["viewkey"] = {
        "protocol": PROTOCOL,
        "audience": vk.audience,
        "fields": field_list,
        "original_hash": b64u(original_hash),
        "tag": b64u(tag),
    }
    return out


def verify_lens(lensed: dict, vk: ViewKey) -> Tuple[bool, str]:
    """Verify a lensed receipt was produced under the given ViewKey.

    Does NOT verify the underlying HAHS/SpectralZK signature — that is a
    separate step. ViewKey only verifies the disclosure envelope.
    """
    try:
        meta = lensed.get("viewkey")
        if not isinstance(meta, dict):
            return False, "missing viewkey envelope"
        if meta.get("protocol") != PROTOCOL:
            return False, f"unknown viewkey protocol: {meta.get('protocol')}"
        if meta.get("audience") != vk.audience:
            return False, f"audience mismatch: envelope={meta.get('audience')} key={vk.audience}"

        field_list = meta.get("fields")
        if not isinstance(field_list, list):
            return False, "viewkey.fields must be a list"

        projection = {k: v for k, v in lensed.items() if k != "viewkey"}
        # Only the declared field set must be present
        for f in projection.keys():
            if f not in field_list:
                return False, f"undeclared field disclosed: {f}"

        projection_hash = canonical_hash(projection)
        tag_input = jcs({
            "protocol": PROTOCOL,
            "audience": vk.audience,
            "fields": field_list,
            "original_hash": meta["original_hash"],
            "projection_hash": b64u(projection_hash),
        })
        expected = hmac.new(vk.key, tag_input, hashlib.sha256).digest()
        claimed = b64u_decode(meta["tag"])
        if not hmac.compare_digest(expected, claimed):
            return False, "viewkey tag mismatch (lens was tampered)"

        return True, "viewkey lens verified"
    except KeyError as e:
        return False, f"missing required viewkey field: {e}"
    except Exception as e:
        return False, f"viewkey verification error: {type(e).__name__}: {e}"
