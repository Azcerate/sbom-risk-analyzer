"""CLI: ingest an SBOM, enrich, score, and report."""
from __future__ import annotations
import argparse, json, sys, dataclasses
from collections import Counter
from .parse import load_sbom
from .enrich import query_osv, enrich_epss, load_kev
from .score import score_one, rank, Risk
from . import __version__


def analyze(path: str, offline_fixture: str | None = None) -> list[Risk]:
    comps = load_sbom(path)
    risks: list[Risk] = []
    if offline_fixture:
        with open(offline_fixture, encoding="utf-8") as fh:
            fixture = json.load(fh)
        kev = set(fixture.get("kev", []))
        vulnmap = fixture.get("vulns", {})
        from .enrich import Vuln
        for c in comps:
            for vd in vulnmap.get(c.name, []):
                v = Vuln(vd["id"], vd.get("cve", ""), vd.get("cvss", 0.0), vd.get("summary", ""))
                v.epss = vd.get("epss", 0.0)
                v.kev = v.cve in kev
                risks.append(score_one(c, v))
        return rank(risks)

    kev = load_kev()
    for c in comps:
        vulns = query_osv(c)
        enrich_epss(vulns)
        for v in vulns:
            v.kev = v.cve in kev
            risks.append(score_one(c, v))
    return rank(risks)


def to_markdown(path: str, risks: list[Risk]) -> str:
    counts = Counter(r.tier for r in risks)
    lines = [
        f"# SBOM Risk Report: {path}", "",
        "## Summary", "",
        f"- Vulnerable findings: **{len(risks)}**",
        f"- Critical (KEV): **{counts.get('Critical',0)}** · High: **{counts.get('High',0)}** "
        f"· Medium: **{counts.get('Medium',0)}** · Low: **{counts.get('Low',0)}**",
        "",
        "Priority = CVSS x exploitability (CISA KEV + FIRST EPSS). Fix Critical/High first.",
        "",
        "| Priority | Component | CVE | CVSS | EPSS | KEV | Score |",
        "|----------|-----------|-----|------|------|-----|-------|",
    ]
    for r in risks:
        lines.append(f"| {r.tier} | {r.component}@{r.version} | {r.cve or r.vuln_id} | "
                     f"{r.cvss:.1f} | {r.epss:.2f} | {'YES' if r.kev else '-'} | {r.score} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sbomrisk",
        description="Prioritize SBOM components by exploitability (OSV + EPSS + CISA KEV).")
    p.add_argument("sbom", help="CycloneDX or SPDX JSON SBOM")
    p.add_argument("-o", "--output", help="Output file (default stdout)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--offline", metavar="FIXTURE",
                   help="Use a local JSON fixture instead of network calls")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "none"],
                   default="none", help="Exit non-zero if a finding at/above this tier exists")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    try:
        risks = analyze(args.sbom, args.offline)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    out = (json.dumps([dataclasses.asdict(r) for r in risks], indent=2)
           if args.format == "json" else to_markdown(args.sbom, risks))
    if args.output:
        open(args.output, "w", encoding="utf-8").write(out)
        print(f"wrote {len(risks)} findings -> {args.output}", file=sys.stderr)
    else:
        print(out)

    gate = {"critical": {"Critical"},
            "high": {"Critical", "High"},
            "medium": {"Critical", "High", "Medium"},
            "none": set()}[args.fail_on]
    if any(r.tier in gate for r in risks):
        print(f"FAIL: findings at/above '{args.fail_on}' present", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
