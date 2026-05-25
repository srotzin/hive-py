"""Tests for HAHS receipts."""
from __future__ import annotations

import copy

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive import hahs


def _sk():
    return Ed25519PrivateKey.generate()


def _pk_bytes(sk):
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_issue_and_verify_roundtrip():
    sk = _sk()
    r = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk,
    )
    assert r["protocol"] == "hahs/1"
    assert r["receipt_id"].startswith("TGT-")
    ok, reason = hahs.verify(r)
    assert ok, reason


def test_verify_with_explicit_pubkey():
    sk = _sk()
    r = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk,
    )
    ok, _ = hahs.verify(r, issuer_pubkey=_pk_bytes(sk))
    assert ok


def test_tamper_amount_fails():
    sk = _sk()
    r = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk,
    )
    bad = copy.deepcopy(r)
    bad["amount_usd"] = 99999.0
    ok, reason = hahs.verify(bad)
    assert not ok
    assert "tamper" in reason.lower() or "verify" in reason.lower()


def test_tamper_recipient_fails():
    sk = _sk()
    r = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk,
    )
    bad = copy.deepcopy(r)
    bad["recipient"] = "evil.api"
    ok, _ = hahs.verify(bad)
    assert not ok


def test_swap_pubkey_fails():
    sk1 = _sk()
    sk2 = _sk()
    r = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk1,
    )
    ok, _ = hahs.verify(r, issuer_pubkey=_pk_bytes(sk2))
    assert not ok


def test_unknown_protocol_fails():
    sk = _sk()
    r = hahs.issue(
        symbol="x", units=1, amount_usd=1.0, recipient="x", issuer_sk=sk,
    )
    r["protocol"] = "hahs/99"
    ok, reason = hahs.verify(r)
    assert not ok
    assert "protocol" in reason
