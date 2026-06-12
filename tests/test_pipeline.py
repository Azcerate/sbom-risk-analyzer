import pathlib
from sbomrisk.parse import load_sbom
from sbomrisk.cli import analyze, to_markdown

ROOT = pathlib.Path(__file__).resolve().parents[1]
SBOM = str(ROOT / "examples" / "sbom.cyclonedx.json")
FIX = str(ROOT / "examples" / "offline_fixture.json")


def test_parse_cyclonedx():
    comps = load_sbom(SBOM)
    assert len(comps) == 4
    assert any(c.name == "log4j-core" for c in comps)


def test_offline_scoring_and_ranking():
    risks = analyze(SBOM, FIX)
    assert risks[0].tier == "Critical"          # log4shell is KEV -> top
    assert risks[0].component == "log4j-core"
    assert risks[0].kev is True


def test_kev_outranks_higher_cvss():
    risks = analyze(SBOM, FIX)
    # requests has cvss 9.8 (no KEV); log4j 10.0 + KEV must still be first
    tiers = [r.tier for r in risks]
    assert tiers[0] == "Critical"


def test_markdown_report():
    md = to_markdown(SBOM, analyze(SBOM, FIX))
    assert "SBOM Risk Report" in md and "KEV" in md
