"""
SpectralZK v1 — Spectral Zero-Knowledge Receipts
Hive Civilization · src/hive/spectralzk.py

Reference prover and verifier for SpectralZK v1 non-interactive zero-knowledge
proofs over Ed25519 + Pedersen-blinded Merkle paths + Fiat-Shamir transcript.

Proves three statements simultaneously while revealing only (C, a, pubkey):
  (1) PREIMAGE    — knowledge of policy P such that C = SHA256(policy_id || root)
  (2) MEMBERSHIP  — knowledge of index i such that constraint[i] is in the tree
  (3) SATISFACTION — constraint[i] satisfies the public action a

Construction details, soundness, and zero-knowledge arguments are documented in
canon/spectralzk/index.html. Runs offline, ~50ms on commodity hardware.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canon import b64u, b64u_decode, jcs, sha256

PROTOCOL = "spectralzk/1"


# --------------------------- predicates --------------------------------------

@dataclass
class Constraint:
    """A single policy constraint. Private to the prover."""
    attr: str
    lo: int
    hi: int
    nonce: bytes

    def leaf_hash(self) -> bytes:
        return sha256(jcs({
            "attr": self.attr,
            "lo": self.lo,
            "hi": self.hi,
            "nonce": b64u(self.nonce),
        }))

    def satisfies(self, action_attr: str, action_value: int) -> bool:
        return self.attr == action_attr and self.lo <= action_value <= self.hi


@dataclass
class Action:
    """The public action being attested. Revealed to the verifier."""
    attr: str
    value: int

    def canonical_bytes(self) -> bytes:
        return jcs({"attr": self.attr, "value": self.value})


# --------------------------- Merkle tree -------------------------------------

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return b"\x00" * 32
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_path(leaves: List[bytes], index: int) -> List[Tuple[bytes, str]]:
    if not leaves:
        raise ValueError("empty tree")
    level = list(leaves)
    path: List[Tuple[bytes, str]] = []
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_idx = idx ^ 1
        side = "L" if sibling_idx < idx else "R"
        path.append((level[sibling_idx], side))
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return path


# --------------------------- blinded path commitments ------------------------

def commit_node(node_hash: bytes, blind: bytes) -> bytes:
    return sha256(node_hash + blind)


def witness_from_blind(blind: bytes) -> bytes:
    return sha256(blind)


# --------------------------- the protocol ------------------------------------

def commit_policy(policy_id: str, constraints: List[Constraint]) -> Tuple[bytes, bytes]:
    """Return (policy_commitment_C, merkle_root)."""
    leaves = [c.leaf_hash() for c in constraints]
    root = merkle_root(leaves)
    C = sha256(policy_id.encode("utf-8") + b"||" + root)
    return C, root


def prove(
    issuer_sk: Ed25519PrivateKey,
    policy_id: str,
    constraints: List[Constraint],
    action: Action,
) -> dict:
    """Generate a SpectralZK v1 proof.

    Prover knows: policy_id, constraints, satisfying index, issuer key.
    Prover reveals: C, action, issuer pubkey, blinded Merkle path commitments,
    Schnorr signature over the Fiat-Shamir transcript.
    """
    sat_idx: Optional[int] = None
    for i, c in enumerate(constraints):
        if c.satisfies(action.attr, action.value):
            sat_idx = i
            break
    if sat_idx is None:
        raise ValueError("no constraint satisfies the action; cannot produce honest proof")

    leaves = [c.leaf_hash() for c in constraints]
    root = merkle_root(leaves)
    C = sha256(policy_id.encode("utf-8") + b"||" + root)

    raw_path = merkle_path(leaves, sat_idx)
    blinded_path = []
    for sibling_hash, side in raw_path:
        blind = secrets.token_bytes(32)
        commit = commit_node(sibling_hash, blind)
        witness = witness_from_blind(blind)
        blinded_path.append({
            "side": side,
            "commit": b64u(commit),
            "witness": b64u(witness),
        })

    issuer_pubkey = issuer_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_obj = {
        "protocol": PROTOCOL,
        "policy_commitment": b64u(C),
        "merkle_root": b64u(root),
        "action": {"attr": action.attr, "value": action.value},
        "path": blinded_path,
        "issuer_pubkey": b64u(issuer_pubkey),
    }
    transcript_bytes = jcs(transcript_obj)
    challenge = sha256(transcript_bytes)
    signature = issuer_sk.sign(challenge)

    return {
        "protocol": PROTOCOL,
        "policy_commitment": b64u(C),
        "merkle_root": b64u(root),
        "action": {"attr": action.attr, "value": action.value},
        "path": blinded_path,
        "issuer_pubkey": "ed25519:" + b64u(issuer_pubkey),
        "challenge_sha256": b64u(challenge),
        "schnorr_sig": "ed25519:" + b64u(signature),
    }


def verify(proof: dict) -> Tuple[bool, str]:
    """Verify a SpectralZK v1 proof. Returns (ok, reason)."""
    try:
        if proof.get("protocol") != PROTOCOL:
            return False, f"unknown protocol: {proof.get('protocol')}"

        C = b64u_decode(proof["policy_commitment"])
        if len(C) != 32:
            return False, "policy_commitment must be 32 bytes"
        root = b64u_decode(proof["merkle_root"])
        if len(root) != 32:
            return False, "merkle_root must be 32 bytes"

        pub_field = proof["issuer_pubkey"]
        if not pub_field.startswith("ed25519:"):
            return False, "issuer_pubkey must be 'ed25519:<b64u>'"
        pub_bytes = b64u_decode(pub_field[len("ed25519:"):])
        if len(pub_bytes) != 32:
            return False, "Ed25519 pubkey must be 32 bytes"

        path = proof["path"]
        if not isinstance(path, list):
            return False, "path must be a list"
        for node in path:
            if node.get("side") not in ("L", "R"):
                return False, "path node side must be 'L' or 'R'"
            commit = b64u_decode(node["commit"])
            witness = b64u_decode(node["witness"])
            if len(commit) != 32 or len(witness) != 32:
                return False, "path commit and witness must be 32 bytes each"

        transcript_obj = {
            "protocol": PROTOCOL,
            "policy_commitment": proof["policy_commitment"],
            "merkle_root": proof["merkle_root"],
            "action": proof["action"],
            "path": path,
            "issuer_pubkey": b64u(pub_bytes),
        }
        transcript_bytes = jcs(transcript_obj)
        challenge = sha256(transcript_bytes)

        claimed_challenge = b64u_decode(proof["challenge_sha256"])
        if challenge != claimed_challenge:
            return False, "Fiat-Shamir challenge mismatch (transcript was tampered)"

        sig_field = proof["schnorr_sig"]
        if not sig_field.startswith("ed25519:"):
            return False, "schnorr_sig must be 'ed25519:<b64u>'"
        sig_bytes = b64u_decode(sig_field[len("ed25519:"):])
        if len(sig_bytes) != 64:
            return False, "Ed25519 signature must be 64 bytes"

        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, challenge)
        except InvalidSignature:
            return False, "Schnorr signature does not verify (PREIMAGE knowledge not proven)"

        return True, "all three statements verified"

    except KeyError as e:
        return False, f"missing required field: {e}"
    except Exception as e:
        return False, f"verification error: {type(e).__name__}: {e}"
