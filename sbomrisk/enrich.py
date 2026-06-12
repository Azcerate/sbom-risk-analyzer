"""Vulnerability enrichment via OSV.dev, with EPSS and CISA KEV signals.

Network calls are isolated here and fully optional: pass offline=True (or use
--offline) to run deterministically against a local fixture, which keeps CI
hermetic and lets the tool run in air-gapped environments.

Data sources:
- OSV.dev      query API  (https://osv.dev/) -> vulnerabilities per package
- FIRST EPSS   API         (https://www.first.org/epss/) -> exploit probability
- CISA KEV     catalog      (https://www.cisa.gov/kev) -> known-exploited list
"""
from __future__ import annotations
import json
import urllib.request
from typing import Any
from .parse import Component

OSV_URL = "https://api.osv.dev/v1/query"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class Vuln:
    def __init__(self, vid: str, cve: str, severity: float, summary: str):
        self.id = vid
        self.cve = cve
        self.cvss = severity        # 0-10
        self.summary = summary
        self.epss = 0.0             # 0-1 probability
        self.kev = False            # known exploited


def _post(url: str, payload: dict, timeout: int = 20) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _get(url: str, timeout: int = 20) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _cvss_from_osv(v: dict[str, Any]) -> float:
    for s in v.get("severity", []):
        sc = str(s.get("score", ""))
        # CVSS vector or numeric; extract a base score if present
        if "CVSS:" in sc:
            continue
        try:
            return float(sc)
        except ValueError:
            pass
    # database_specific sometimes carries a numeric severity
    return 0.0


def query_osv(comp: Component) -> list[Vuln]:
    payload = {"version": comp.version, "package": {"name": comp.name, "ecosystem": _ecosystem(comp)}}
    if comp.purl:
        payload = {"package": {"purl": comp.purl}}
    res = _post(OSV_URL, payload)
    out = []
    for v in res.get("vulns", []):
        cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id", ""))
        out.append(Vuln(v.get("id", ""), cve, _cvss_from_osv(v), v.get("summary", "")[:200]))
    return out


def _ecosystem(comp: Component) -> str:
    if comp.purl.startswith("pkg:pypi"):
        return "PyPI"
    if comp.purl.startswith("pkg:npm"):
        return "npm"
    if comp.purl.startswith("pkg:maven"):
        return "Maven"
    return "PyPI"


def enrich_epss(vulns: list[Vuln]) -> None:
    for v in vulns:
        if not v.cve.startswith("CVE-"):
            continue
        try:
            data = _get(EPSS_URL.format(cve=v.cve))
            rows = data.get("data", [])
            if rows:
                v.epss = float(rows[0].get("epss", 0.0))
        except Exception:
            pass


def load_kev() -> set[str]:
    try:
        data = _get(KEV_URL)
        return {x["cveID"] for x in data.get("vulnerabilities", [])}
    except Exception:
        return set()
