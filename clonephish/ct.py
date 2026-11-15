"""Certificate Transparency lookup via crt.sh.

Finds certificates issued for names containing your brand keyword, then runs
each name through the lookalike scorer. Needs internet access.
"""

from __future__ import annotations

import requests

from .domains import analyse_domain, clean_host, split_domain

CRT_SH = "https://crt.sh/"


def fetch_ct_names(keyword: str, timeout: int = 60) -> set[str]:
    """Return unique hostnames from crt.sh certificates matching %keyword%."""
    resp = requests.get(
        CRT_SH,
        params={"q": f"%{keyword}%", "output": "json"},
        headers={"User-Agent": "clonephish-detector/0.1 (defensive research)"},
        timeout=timeout,
    )
    resp.raise_for_status()
    names: set[str] = set()
    for entry in resp.json():
        for name in str(entry.get("name_value", "")).splitlines():
            name = clean_host(name.lstrip("*."))
            if name:
                names.add(name)
    return names


def scan_ct(brand: str, keyword: str | None = None, min_score: int = 40):
    """Look up CT logs for the brand keyword and score every name found."""
    brand_host = clean_host(brand)
    keyword = keyword or split_domain(brand_host)[1]
    results = []
    for name in sorted(fetch_ct_names(keyword)):
        finding = analyse_domain(name, brand_host)
        if finding.score >= min_score:
            results.append(finding)
    return sorted(results, key=lambda f: f.score, reverse=True)
