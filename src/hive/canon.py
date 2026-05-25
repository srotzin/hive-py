"""Canonical encoding and hashing utilities shared by all primitives.

All four Hive primitives sign over RFC 8785 JSON Canonicalization Scheme
(JCS) bytes. This module is the single point of truth for the encoding so
prover and verifier produce byte-identical transcripts.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


def jcs(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (subset): sort keys, no whitespace, UTF-8.

    The full RFC 8785 also normalizes numbers via I-JSON; for the Hive
    primitives we restrict numeric inputs to integers and strings so this
    subset is byte-identical to a full RFC 8785 implementation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data: bytes) -> bytes:
    """SHA-256 digest of bytes. 32 bytes."""
    return hashlib.sha256(data).digest()


def b64u(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Base64url-decode without padding."""
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def canonical_hash(obj: Any) -> bytes:
    """SHA-256(JCS(obj)). The Hive canonical hash."""
    return sha256(jcs(obj))


def canonical_hash_b64u(obj: Any) -> str:
    """Base64url canonical hash. Useful for receipt headers."""
    return b64u(canonical_hash(obj))
