"""Parse CycloneDX and SPDX SBOMs into a normalized component list.

Each component: {name, version, purl, type}. purl (Package URL) is used as the
key for vulnerability lookups (OSV accepts purl directly).
"""
from __future__ import annotations
import json
from typing import Any


class Component:
    __slots__ = ("name", "version", "purl", "ctype")

    def __init__(self, name: str, version: str, purl: str = "", ctype: str = "library"):
        self.name = name
        self.version = version
        self.purl = purl
        self.ctype = ctype

    def key(self) -> str:
        return self.purl or f"{self.name}@{self.version}"

    def __repr__(self) -> str:
        return f"Component({self.name}@{self.version})"


def _detect(doc: dict[str, Any]) -> str:
    if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
        return "cyclonedx"
    if doc.get("spdxVersion") or "packages" in doc:
        return "spdx"
    raise ValueError("Unrecognized SBOM format (expected CycloneDX or SPDX JSON)")


def _from_cyclonedx(doc: dict[str, Any]) -> list[Component]:
    out = []
    for c in doc.get("components", []):
        out.append(Component(
            name=c.get("name", "unknown"),
            version=str(c.get("version", "")),
            purl=c.get("purl", ""),
            ctype=c.get("type", "library"),
        ))
    return out


def _from_spdx(doc: dict[str, Any]) -> list[Component]:
    out = []
    for p in doc.get("packages", []):
        purl = ""
        for ref in p.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break
        out.append(Component(
            name=p.get("name", "unknown"),
            version=str(p.get("versionInfo", "")),
            purl=purl,
            ctype="library",
        ))
    return out


def load_sbom(path: str) -> list[Component]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    fmt = _detect(doc)
    comps = _from_cyclonedx(doc) if fmt == "cyclonedx" else _from_spdx(doc)
    # de-dupe by key
    seen, uniq = set(), []
    for c in comps:
        if c.key() not in seen:
            seen.add(c.key())
            uniq.append(c)
    return uniq
