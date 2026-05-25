"""Tests for SHOD six-gate governance."""
from __future__ import annotations

from hive.shod import GateStack, TransactionContext


def test_allowlist_blocks_unknown_recipient():
    g = GateStack.default(allowlist=["acme.api"])
    r = g.evaluate(recipient="evil.api", amount_usd=10)
    assert not r.ok
    assert any("ALLOWLIST" in x for x in r.reasons)


def test_daily_cap_blocks_overrun():
    g = GateStack.default(daily_cap_usd=100)
    r = g.evaluate(
        recipient="acme.api", amount_usd=50,
        ctx=TransactionContext(spent_today_usd=80),
    )
    assert not r.ok
    assert any("DAILY_CAP" in x for x in r.reasons)


def test_per_recipient_cap_blocks_overrun():
    g = GateStack.default(per_recipient_cap_usd=200)
    r = g.evaluate(
        recipient="acme.api", amount_usd=100,
        ctx=TransactionContext(spent_to_recipient_usd=150),
    )
    assert not r.ok
    assert any("PER_RECIPIENT" in x for x in r.reasons)


def test_price_window_enforced():
    g = GateStack.default(price_window=(0.001, 0.01), anomaly_zmax=None)
    r = g.evaluate(recipient="x", amount_usd=10, unit_price_usd=0.05)
    assert not r.ok
    r2 = g.evaluate(recipient="x", amount_usd=10, unit_price_usd=0.005)
    assert r2.ok


def test_trust_tier_minimum():
    g = GateStack.default(min_trust_tier=3)
    r = g.evaluate(
        recipient="x", amount_usd=10,
        ctx=TransactionContext(recipient_trust_tier=1),
    )
    assert not r.ok


def test_anomaly_zscore():
    g = GateStack.default(anomaly_zmax=3.0)
    r = g.evaluate(
        recipient="x", amount_usd=10000,
        ctx=TransactionContext(rolling_mean_usd=10, rolling_std_usd=1),
    )
    assert not r.ok
    assert any("ANOMALY" in x for x in r.reasons)


def test_all_pass():
    g = GateStack.default(
        allowlist=["acme.api"],
        daily_cap_usd=500,
        per_recipient_cap_usd=200,
        price_window=(0.001, 0.01),
        min_trust_tier=2,
        anomaly_zmax=4.0,
    )
    r = g.evaluate(
        recipient="acme.api", amount_usd=145, unit_price_usd=0.005,
        ctx=TransactionContext(
            spent_today_usd=100, spent_to_recipient_usd=50,
            recipient_trust_tier=3,
            rolling_mean_usd=140, rolling_std_usd=20,
        ),
    )
    assert r.ok, r.reasons
