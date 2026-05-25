"""Tests for ViewKey selective disclosure."""
from __future__ import annotations

import copy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive import hahs, viewkey
from hive.viewkey import (
    AUDIENCE_COUNTERPARTY,
    AUDIENCE_REGULATOR,
    ViewKey,
)


def _receipt():
    sk = Ed25519PrivateKey.generate()
    return hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="acme.api",
        issuer_sk=sk,
    )


def test_regulator_lens_strips_recipient():
    r = _receipt()
    vk = ViewKey.generate(AUDIENCE_REGULATOR)
    lensed = viewkey.lens(r, vk)
    # Regulator lens MUST NOT contain recipient
    assert "recipient" not in lensed
    # Should contain audit-essential fields
    assert "canonical_sha256" in lensed
    assert "signature" in lensed
    ok, reason = viewkey.verify_lens(lensed, vk)
    assert ok, reason


def test_counterparty_lens_keeps_recipient():
    r = _receipt()
    vk = ViewKey.generate(AUDIENCE_COUNTERPARTY)
    lensed = viewkey.lens(r, vk)
    assert "recipient" in lensed
    ok, _ = viewkey.verify_lens(lensed, vk)
    assert ok


def test_tamper_lens_fails():
    r = _receipt()
    vk = ViewKey.generate(AUDIENCE_REGULATOR)
    lensed = viewkey.lens(r, vk)
    bad = copy.deepcopy(lensed)
    bad["amount_usd"] = 99999.0
    ok, reason = viewkey.verify_lens(bad, vk)
    assert not ok
    assert "tamper" in reason.lower() or "mismatch" in reason.lower()


def test_wrong_key_fails():
    r = _receipt()
    vk = ViewKey.generate(AUDIENCE_REGULATOR)
    lensed = viewkey.lens(r, vk)
    wrong = ViewKey.generate(AUDIENCE_REGULATOR)
    ok, _ = viewkey.verify_lens(lensed, wrong)
    assert not ok


def test_undeclared_field_disclosure_fails():
    r = _receipt()
    vk = ViewKey.generate(AUDIENCE_REGULATOR)
    lensed = viewkey.lens(r, vk)
    bad = copy.deepcopy(lensed)
    bad["secret_field"] = "leaked"
    ok, reason = viewkey.verify_lens(bad, vk)
    assert not ok


def test_viewkey_b64u_roundtrip():
    vk = ViewKey.generate(AUDIENCE_REGULATOR)
    s = vk.to_b64u()
    restored = ViewKey.from_b64u(s)
    assert restored.audience == vk.audience
    assert restored.key == vk.key
