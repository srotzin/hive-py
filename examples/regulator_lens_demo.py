"""
regulator_lens_demo.py — show holder vs regulator vs counterparty disclosure.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hive import hahs, viewkey
from hive.viewkey import (
    AUDIENCE_COUNTERPARTY,
    AUDIENCE_HOLDER,
    AUDIENCE_REGULATOR,
    ViewKey,
)


def main():
    sk = Ed25519PrivateKey.generate()
    receipt = hahs.issue(
        symbol="SIU-LLM70B-T0-ZK-US",
        units=25000,
        amount_usd=145.0,
        recipient="openrouter.ai",
        issuer_sk=sk,
        hahs_anchor="base:#19284733",
        settlement="usdc-base",
    )

    for audience in (AUDIENCE_HOLDER, AUDIENCE_REGULATOR, AUDIENCE_COUNTERPARTY):
        vk = ViewKey.generate(audience)
        lensed = viewkey.lens(receipt, vk)
        ok, _ = viewkey.verify_lens(lensed, vk)
        print(f"--- audience = {audience}  (verify: {ok}) ---")
        for k in sorted(lensed.keys()):
            if k == "viewkey":
                continue
            print(f"  {k}: {lensed[k]}")
        print()


if __name__ == "__main__":
    main()
