"""SHOD — Six-gate Hardware Outbound Domain governance.

SHOD enforces six independent gates on every outbound agent payment
*before* the issuer's signing key can sign:

    1. ALLOWLIST       recipient must be in the policy's allowed set
    2. DAILY_CAP       cumulative spend today must remain below cap
    3. PER_RECIPIENT   per-recipient spend window must not be exceeded
    4. PRICE_WINDOW    unit price must fall within issuer-defined band
    5. TRUST_TIER      recipient's trust tier must meet minimum
    6. ANOMALY         z-score against rolling baseline must be within bound

A failure on any gate halts the transaction at signature time. Overruns
become physically impossible because the signing key is gated behind the
evaluator. This module provides the policy evaluator; in production the
key material itself is bound to the evaluator via HSM or TEE attestation.

The evaluator is deterministic. Two calls with identical inputs produce
identical results. This is essential for replay verification by an
auditor with the same policy + history snapshot.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass
class GateConfig:
    """Configuration for the six gates. Fields are optional; an unset gate
    is treated as a pass (the evaluator records 'gate skipped' but does
    not block)."""
    allowlist: Optional[list] = None
    daily_cap_usd: Optional[float] = None
    per_recipient_cap_usd: Optional[float] = None
    price_window: Optional[Tuple[float, float]] = None
    min_trust_tier: Optional[int] = None
    anomaly_zmax: Optional[float] = None


@dataclass
class TransactionContext:
    """Runtime state the evaluator consults. Caller is responsible for
    keeping this fresh — typically pulled from a SHOD ledger snapshot."""
    spent_today_usd: float = 0.0
    spent_to_recipient_usd: float = 0.0
    recipient_trust_tier: int = 0
    rolling_mean_usd: float = 0.0
    rolling_std_usd: float = 1.0


@dataclass
class GateResult:
    """The full result of a six-gate evaluation. `ok` is True iff every
    enforced gate passed."""
    ok: bool
    reasons: list = field(default_factory=list)
    gate_log: list = field(default_factory=list)

    def short(self) -> str:
        if self.ok:
            return "SHOD PASS — " + ", ".join(self.gate_log)
        return "SHOD FAIL — " + "; ".join(self.reasons)


class GateStack:
    """The six-gate outbound governance stack."""

    def __init__(self, config: GateConfig):
        self.config = config

    @classmethod
    def default(
        cls,
        *,
        allowlist: Optional[list] = None,
        daily_cap_usd: Optional[float] = None,
        per_recipient_cap_usd: Optional[float] = None,
        price_window: Optional[Tuple[float, float]] = None,
        min_trust_tier: Optional[int] = None,
        anomaly_zmax: Optional[float] = 4.0,
    ) -> "GateStack":
        """Build a GateStack with a sensible default anomaly bound."""
        return cls(GateConfig(
            allowlist=allowlist,
            daily_cap_usd=daily_cap_usd,
            per_recipient_cap_usd=per_recipient_cap_usd,
            price_window=price_window,
            min_trust_tier=min_trust_tier,
            anomaly_zmax=anomaly_zmax,
        ))

    def evaluate(
        self,
        *,
        recipient: str,
        amount_usd: float,
        unit_price_usd: Optional[float] = None,
        ctx: Optional[TransactionContext] = None,
    ) -> GateResult:
        """Run all six gates. Returns a GateResult."""
        ctx = ctx or TransactionContext()
        cfg = self.config
        reasons: list = []
        log: list = []

        # 1. ALLOWLIST
        if cfg.allowlist is not None:
            if recipient not in cfg.allowlist:
                reasons.append(f"ALLOWLIST: '{recipient}' not in allowlist")
            else:
                log.append("ALLOWLIST ok")
        else:
            log.append("ALLOWLIST skipped")

        # 2. DAILY_CAP
        if cfg.daily_cap_usd is not None:
            if ctx.spent_today_usd + amount_usd > cfg.daily_cap_usd:
                reasons.append(
                    f"DAILY_CAP: {ctx.spent_today_usd + amount_usd:.2f} > {cfg.daily_cap_usd:.2f} USD"
                )
            else:
                log.append(f"DAILY_CAP ok ({ctx.spent_today_usd + amount_usd:.2f}/{cfg.daily_cap_usd:.2f})")
        else:
            log.append("DAILY_CAP skipped")

        # 3. PER_RECIPIENT
        if cfg.per_recipient_cap_usd is not None:
            if ctx.spent_to_recipient_usd + amount_usd > cfg.per_recipient_cap_usd:
                reasons.append(
                    f"PER_RECIPIENT: {ctx.spent_to_recipient_usd + amount_usd:.2f} > {cfg.per_recipient_cap_usd:.2f} USD"
                )
            else:
                log.append(f"PER_RECIPIENT ok ({ctx.spent_to_recipient_usd + amount_usd:.2f}/{cfg.per_recipient_cap_usd:.2f})")
        else:
            log.append("PER_RECIPIENT skipped")

        # 4. PRICE_WINDOW
        if cfg.price_window is not None and unit_price_usd is not None:
            lo, hi = cfg.price_window
            if not (lo <= unit_price_usd <= hi):
                reasons.append(f"PRICE_WINDOW: unit_price {unit_price_usd} outside [{lo}, {hi}]")
            else:
                log.append(f"PRICE_WINDOW ok ({unit_price_usd} in [{lo}, {hi}])")
        else:
            log.append("PRICE_WINDOW skipped")

        # 5. TRUST_TIER
        if cfg.min_trust_tier is not None:
            if ctx.recipient_trust_tier < cfg.min_trust_tier:
                reasons.append(
                    f"TRUST_TIER: recipient tier {ctx.recipient_trust_tier} < min {cfg.min_trust_tier}"
                )
            else:
                log.append(f"TRUST_TIER ok ({ctx.recipient_trust_tier} >= {cfg.min_trust_tier})")
        else:
            log.append("TRUST_TIER skipped")

        # 6. ANOMALY (z-score)
        if cfg.anomaly_zmax is not None and ctx.rolling_std_usd > 0:
            z = (amount_usd - ctx.rolling_mean_usd) / ctx.rolling_std_usd
            if math.fabs(z) > cfg.anomaly_zmax:
                reasons.append(f"ANOMALY: z={z:.2f} > zmax={cfg.anomaly_zmax}")
            else:
                log.append(f"ANOMALY ok (z={z:.2f})")
        else:
            log.append("ANOMALY skipped")

        return GateResult(ok=(len(reasons) == 0), reasons=reasons, gate_log=log)


__all__ = ["GateConfig", "TransactionContext", "GateResult", "GateStack"]
