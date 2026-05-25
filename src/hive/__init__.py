"""Hive Civilization SDK.

Four canonical primitives for autonomous-agent commerce:

    HAHS         signed receipts with canonical SHA-256 anchor
    SpectralZK   non-interactive zero-knowledge proof of policy-bound action
    SHOD         six-gate outbound governance enforced at signature time
    ViewKey      selective-disclosure receipts with deterministic lenses

Pure Python. Standalone. No network calls. No external prover network.
The math is the prover.

    >>> import hive
    >>> from hive import shod, hahs, spectralzk, viewkey
    >>> gate = shod.GateStack.default(daily_cap_usd=500, allowlist=["acme.api"])
    >>> result = gate.evaluate(recipient="acme.api", amount_usd=145)
    >>> if result.ok:
    ...     receipt = hahs.issue(symbol="SIU-LLM70B-T0-ZK-US",
    ...                          units=25000, amount_usd=145,
    ...                          recipient="acme.api", issuer_sk=sk)
    ...     print(hahs.verify(receipt, issuer_pubkey=pk))
    (True, 'all four checks verified')

Full docs:   https://thehiveryiq.com/canon/
Patents:     https://thehiveryiq.com/canon/spectralzk/  (HIVE-2026-SZK-001)
Source:      https://github.com/thehivery/hive-py
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Hive Civilization"
__license__ = "MIT (+ patent grant for SpectralZK; see LICENSE)"

from hive import hahs, spectralzk, shod, viewkey, canon

__all__ = ["hahs", "spectralzk", "shod", "viewkey", "canon", "__version__"]
