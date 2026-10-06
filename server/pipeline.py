"""Configurable ordering of the two security stages (rate limiter, WAF)."""

import os
from dataclasses import dataclass
from typing import Optional

RATE_LIMIT_FIRST = "rate_limit_first"   # Mode A
WAF_FIRST = "waf_first"                 # Mode B
ORDERS = (RATE_LIMIT_FIRST, WAF_FIRST)
DEFAULT_ORDER = RATE_LIMIT_FIRST
ENV_VAR = "PIPELINE_ORDER"

STAGE_RATE_LIMITER = "rate_limiter"
STAGE_WAF = "waf"


@dataclass(frozen=True)
class PipelineResult:
    allowed: bool
    status: int = 200                 # 200 allowed, 429 rate limited, 403 WAF
    stage: Optional[str] = None       # which stage rejected
    retry_after: Optional[int] = None
    waf: Optional[object] = None      # WafResult when the WAF rejected


def parse_order(value):
    order = (value or DEFAULT_ORDER).strip().lower()
    if order not in ORDERS:
        raise ValueError("invalid %s=%r (expected one of %s)"
                         % (ENV_VAR, value, ", ".join(ORDERS)))
    return order


class Pipeline:
    def __init__(self, rate_limiter, waf, order=DEFAULT_ORDER):
        self.order = parse_order(order)
        self._rate_limiter = rate_limiter
        self._waf = waf
        if self.order == RATE_LIMIT_FIRST:
            self._stages = (self._rate_limit_stage, self._waf_stage)
        else:
            self._stages = (self._waf_stage, self._rate_limit_stage)

    @classmethod
    def from_env(cls, rate_limiter, waf):
        return cls(rate_limiter, waf, os.environ.get(ENV_VAR, DEFAULT_ORDER))

    def process(self, request, normalized):
        """Run stages in order; the first rejection wins and later stages never run."""
        for stage in self._stages:
            rejection = stage(request, normalized)
            if rejection is not None:
                return rejection
        return PipelineResult(True)

    def _rate_limit_stage(self, request, normalized):
        decision = self._rate_limiter.allow(getattr(request, "client_ip", None))
        if decision.allowed:
            return None
        return PipelineResult(False, 429, STAGE_RATE_LIMITER,
                              retry_after=decision.retry_after)

    def _waf_stage(self, request, normalized):
        verdict = self._waf.inspect(normalized)
        if verdict.allowed:
            return None
        return PipelineResult(False, 403, STAGE_WAF, waf=verdict)