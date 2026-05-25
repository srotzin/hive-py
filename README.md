# hive-protocol

Reference Python SDK for the **Hive Civilization** primitives — the open audit
layer for autonomous-agent commerce.

```
pip install hive-protocol
```

Four primitives. One package. No prover network. No trusted setup. Offline
verify in ~50ms.

| Primitive | What it does |
|-----------|--------------|
| **HAHS**       | Canonical signed receipts. Tre'gent IDs, RFC 8785 JCS, Ed25519. |
| **SpectralZK** | Non-interactive zero-knowledge proof that a public action satisfied a private policy. |
| **SHOD**       | Six-gate outbound governance enforced at signature time. |
| **ViewKey**    | Selective-disclosure lenses (holder / regulator / counterparty). |

The math is the prover. The network is an audience.

## Quickstart

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hive import hahs, shod, spectralzk, viewkey
from hive.spectralzk import Action, Constraint
from hive.viewkey import AUDIENCE_REGULATOR, ViewKey

# 1. Pre-flight outbound governance
gate = shod.GateStack.default(
    allowlist=["openrouter.ai"],
    daily_cap_usd=500,
    price_window=(0.001, 0.02),
)
result = gate.evaluate(recipient="openrouter.ai", amount_usd=145, unit_price_usd=0.0058)
assert result.ok, result.short()

# 2. Sign the receipt
sk = Ed25519PrivateKey.generate()
receipt = hahs.issue(
    symbol="SIU-LLM70B-T0-ZK-US",
    units=25000,
    amount_usd=145.0,
    recipient="openrouter.ai",
    issuer_sk=sk,
)
ok, reason = hahs.verify(receipt)
assert ok

# 3. Lens for regulator audit
vk = ViewKey.generate(AUDIENCE_REGULATOR)
audit_view = viewkey.lens(receipt, vk)        # recipient stripped
assert viewkey.verify_lens(audit_view, vk)[0]
```

Full demo: `python examples/agent_spend_demo.py`

## CLI

```
hive verify <file.json>          # auto-detect HAHS or SpectralZK and verify
hive prove-sample sample.json    # generate a SpectralZK sample proof
hive issue --symbol SIU-X --units 1 --amount 1.50 --recipient acme.api
```

## Why Hive

Today's agentic payment rails (x402, AP2, Onyx, A2A) settle the dollar but
leave no audit trail an enterprise compliance team can defend. Hive adds the
audit layer underneath:

- **Receipts that survive a subpoena.** HAHS signs canonical bytes with the
  issuer key; any change to amount, recipient, or symbol breaks the signature.
- **Hardware-bound spending caps.** SHOD makes overruns physically impossible
  because the signing key is gated behind the six-gate evaluator.
- **Policy-hiding compliance.** SpectralZK proves that an action satisfied a
  private policy without revealing the policy text.
- **Audience-bound disclosure.** ViewKey gives regulators what they need
  without leaking counterparty PII to them.

Designed for SOC-2, ISO 27001, HIPAA, EU AI Act, and MiCA audits out of the
box. Patent: USPTO HIVE-2026-MNK-001 (filed May 23 2026, parent), HIVE-2026-SZK-001
(provisional, SpectralZK NIZK).

## Status

`v0.1.0` — early but stable surface. APIs are frozen for the lifetime of v0.x.

- Site:        https://thehiveryiq.com
- Canon:       https://thehiveryiq.com/canon/
- SpectralZK:  https://thehiveryiq.com/canon/spectralzk/
- Schemas:     https://thehiveryiq.com/.well-known/schemas/

## License

MIT for the SDK. A separate **SpectralZK Patent Grant** is included in
`LICENSE` and gives all SDK users a perpetual, royalty-free, worldwide license
to practice the patent claims when using this SDK.

---

Hive Civilization · founded 2026 · ops@thehiveryiq.com
