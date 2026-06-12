# SBOM-Risk-Analyzer

Turn a **CycloneDX** or **SPDX** SBOM into a **prioritized vulnerability risk
report**. It enriches each component with vulnerability data from **OSV.dev**,
exploit-prediction scores from **FIRST EPSS**, and active-exploitation status
from the **CISA KEV** catalog â€” then ranks findings the way a real
vuln-management program does: *fix what is being exploited first.*

## Why this matters

A raw CVE list sorted by CVSS drowns teams in "criticals" that nobody is
actually exploiting. This tool weights **known-exploited (KEV)** and
**predicted-exploited (EPSS)** signals above raw severity, so the top of the
report is the work that actually reduces risk this week. It runs fully
**offline** against a fixture for hermetic CI and air-gapped environments.

## Install

```bash
pip install -e .          # standard library only, no runtime dependencies
```

## Usage

```bash
# Live enrichment (OSV + EPSS + CISA KEV)
sbomrisk examples/sbom.cyclonedx.json -o risk-report.md

# Offline / deterministic (CI, air-gapped) using a local fixture
sbomrisk examples/sbom.cyclonedx.json --offline examples/offline_fixture.json

# Fail a pipeline if any KEV/Critical finding is present
sbomrisk sbom.json --offline examples/offline_fixture.json --fail-on critical

# JSON for downstream tooling
sbomrisk sbom.json --format json
```

## Scoring model

```
score = CVSS x (1 + 1.5*KEV + 1.0*EPSS)     # clamped to 0..25
tier  = Critical if KEV, else High >=12, Medium >=6, Low otherwise
```

KEV dominates because it means real-world active exploitation. EPSS (0..1
probability) is the next strongest signal. The model is small and documented in
[`sbomrisk/score.py`](sbomrisk/score.py) â€” tune the weights to your risk appetite.

## Example output

| Priority | Component | CVE | CVSS | EPSS | KEV | Score |
|----------|-----------|-----|------|------|-----|-------|
| Critical | log4j-core@2.14.1 | CVE-2021-44228 | 10.0 | 0.97 | YES | 25.0 |
| High | requests@2.19.1 | CVE-2018-18074 | 9.8 | 0.32 | - | 12.94 |
| Medium | lodash@4.17.4 | CVE-2019-10744 | 9.1 | 0.10 | - | 10.01 |

## Data sources

OSV.dev Â· FIRST EPSS API Â· CISA Known Exploited Vulnerabilities catalog.

## Development

```bash
pip install -e . pytest && pytest -q
```

## License

MIT Â© 2026 Anthony N. Saunders
