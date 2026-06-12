"""Risk prioritization.

Priority score blends impact (CVSS) with exploitability signals. KEV (known
exploited) dominates because it means real-world active exploitation; EPSS
(predicted exploitation) is the next strongest signal. This mirrors how mature
vuln-management programs triage: fix what is being exploited first, not just
what has the highest CVSS.

    score = cvss * (1 + 1.5*kev + 1.0*epss)   # clamped to 0..25
    tier:  KEV -> Critical
           score >= 12 -> High
           score >= 6  -> Medium
           else        -> Low
"""
from __future__ import annotations
from dataclasses import dataclass
from .parse import Component
from .enrich import Vuln


@dataclass
class Risk:
    component: str
    version: str
    vuln_id: str
    cve: str
    cvss: float
    epss: float
    kev: bool
    score: float
    tier: str
    summary: str


def score_one(comp: Component, v: Vuln) -> Risk:
    raw = v.cvss * (1 + 1.5 * (1 if v.kev else 0) + 1.0 * v.epss)
    score = round(min(raw, 25.0), 2)
    if v.kev:
        tier = "Critical"
    elif score >= 12:
        tier = "High"
    elif score >= 6:
        tier = "Medium"
    else:
        tier = "Low"
    return Risk(comp.name, comp.version, v.id, v.cve, v.cvss, v.epss, v.kev,
                score, tier, v.summary)


_TIER_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def rank(risks: list[Risk]) -> list[Risk]:
    return sorted(risks, key=lambda r: (_TIER_ORDER[r.tier], -r.score))
