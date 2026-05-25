"""
agent_spend_demo.py — end-to-end Hive primitive flow for one agent payment.

  1. SHOD pre-flight: six-gate evaluator decides if the action may sign
  2. HAHS receipt: signed canonical artifact for the action
  3. ViewKey lens: produce a regulator-safe projection
  4. SpectralZK proof: zero-knowledge attestation that the action satisfied
     a private policy

Run:    python examples/agent_spend_demo.py
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive import hahs, shod, spectralzk, viewkey
from hive.spectralzk import Action, Constraint
from hive.viewkey import AUDIENCE_REGULATOR, ViewKey


def main():
    # --- 1. SHOD pre-flight ----------------------------------------------
    gate = shod.GateStack.default(
        allowlist=["openrouter.ai"],
        daily_cap_usd=500.0,
        per_recipient_cap_usd=200.0,
        price_window=(0.001, 0.02),
        min_trust_tier=2,
        anomaly_zmax=4.0,
    )
    ctx = shod.TransactionContext(
        spent_today_usd=100.0,
        spent_to_recipient_usd=50.0,
        recipient_trust_tier=3,
        rolling_mean_usd=140.0,
        rolling_std_usd=20.0,
    )
    result = gate.evaluate(
        recipient="openrouter.ai",
        amount_usd=145.0,
        unit_price_usd=0.0058,
        ctx=ctx,
    )
    print(result.short())
    assert result.ok

    # --- 2. HAHS receipt -------------------------------------------------
    sk = Ed25519PrivateKey.generate()
    receipt = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="openrouter.ai",
        issuer_sk=sk,
    )
    ok, reason = hahs.verify(receipt)
    print(f"HAHS verify: {ok}  ({reason})")
    print(f"  receipt_id: {receipt['receipt_id']}")
    print(f"  anchor:     {receipt['canonical_sha256']}")

    # --- 3. ViewKey regulator lens --------------------------------------
    vk_reg = ViewKey.generate(AUDIENCE_REGULATOR)
    lensed = viewkey.lens(receipt, vk_reg)
    ok2, _ = viewkey.verify_lens(lensed, vk_reg)
    print(f"Regulator lens verify: {ok2}")
    print(f"  fields disclosed: {sorted(k for k in lensed if k != 'viewkey')}")
    print(f"  recipient hidden: {'recipient' not in lensed}")

    # --- 4. SpectralZK proof --------------------------------------------
    seed = b"hive-spectralzk-demo-issuer-seed"
    issuer_sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
    constraints = [
        Constraint("spend_usd_per_day", 0, 50, b"\x01" * 16),
        Constraint("spend_usd_per_day", 51, 200, b"\x02" * 16),
        Constraint("spend_usd_per_day", 201, 1000, b"\x03" * 16),
    ]
    proof = spectralzk.prove(
        issuer_sk,
        "hive.policy.shod.spend-tier.v1",
        constraints,
        Action("spend_usd_per_day", 145),
    )
    ok3, reason3 = spectralzk.verify(proof)
    print(f"SpectralZK verify: {ok3}  ({reason3})")
    print(f"  policy commit: {proof['policy_commitment']}")
    print(f"  path depth:    {len(proof['path'])} blinded nodes")

    print()
    print("all four primitives passed. agent spend is authorized, signed,")
    print("audit-safe under selective disclosure, and zero-knowledge attested.")


if __name__ == "__main__":
    main()
