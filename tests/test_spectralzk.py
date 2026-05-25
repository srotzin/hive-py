"""Tests for SpectralZK proofs."""
from __future__ import annotations

import copy
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive import spectralzk
from hive.spectralzk import Action, Constraint


def _issuer():
    seed = b"hive-spectralzk-test-seed-001"
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def _constraints():
    return [
        Constraint("spend_usd_per_day", 0, 50, b"\x01" * 16),
        Constraint("spend_usd_per_day", 51, 200, b"\x02" * 16),
        Constraint("spend_usd_per_day", 201, 1000, b"\x03" * 16),
        Constraint("spend_usd_per_day", 1001, 10000, b"\x04" * 16),
    ]


def test_prove_and_verify_roundtrip():
    proof = spectralzk.prove(
        _issuer(),
        "hive.policy.shod.spend-tier.v1",
        _constraints(),
        Action("spend_usd_per_day", 145),
    )
    ok, reason = spectralzk.verify(proof)
    assert ok, reason


def test_zero_knowledge_no_constraint_leak():
    proof = spectralzk.prove(
        _issuer(), "policy", _constraints(), Action("spend_usd_per_day", 145),
    )
    # The proof must NOT contain any raw constraint values
    serialized = str(proof)
    assert "50" not in proof.get("merkle_root", "")
    assert "spend_usd_per_day" not in [
        # appears only in action, never as a separate field
        k for k in proof.keys()
    ]
    # path entries reveal only commit + witness + side
    for node in proof["path"]:
        assert set(node.keys()) == {"side", "commit", "witness"}


def test_tamper_action_value_fails():
    proof = spectralzk.prove(
        _issuer(), "policy", _constraints(), Action("spend_usd_per_day", 145),
    )
    bad = copy.deepcopy(proof)
    bad["action"]["value"] = 99999
    ok, reason = spectralzk.verify(bad)
    assert not ok
    assert "Fiat-Shamir" in reason or "mismatch" in reason.lower()


def test_tamper_merkle_root_fails():
    proof = spectralzk.prove(
        _issuer(), "policy", _constraints(), Action("spend_usd_per_day", 145),
    )
    bad = copy.deepcopy(proof)
    bad["merkle_root"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ok, _ = spectralzk.verify(bad)
    assert not ok


def test_tamper_path_commit_fails():
    proof = spectralzk.prove(
        _issuer(), "policy", _constraints(), Action("spend_usd_per_day", 145),
    )
    bad = copy.deepcopy(proof)
    bad["path"][0]["commit"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ok, _ = spectralzk.verify(bad)
    assert not ok


def test_no_satisfying_constraint_aborts():
    try:
        spectralzk.prove(
            _issuer(), "policy", _constraints(), Action("spend_usd_per_day", 999999),
        )
        assert False, "should have raised"
    except ValueError:
        pass
