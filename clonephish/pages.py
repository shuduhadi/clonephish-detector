"""Cloned-page analysis.

Compares a suspect HTML page with a known-good reference page from the brand
and looks for the fingerprints that copied login pages tend to leave.
Works on saved HTML files, so suspect pages never need to be opened in a
browser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .domains import clean_host


@dataclass
class PageFeatures:
    title: str
    text_shingles: set[str]
    form_fields: set[str]
    asset_names: set[str]
    asset_hosts: set[str]
    form_actions: list[str]
    has_password_field: bool


@dataclass
class PageFinding:
    similarity: float
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        if self.score >= 70:
            return "HIGH"
        if self.score >= 40:
            return "MEDIUM"
        if self.score > 0:
            return "LOW"
        return "NONE"

    def add(self, points: int, reason: str) -> None:
        self.score = min(100, self.score + points)
        self.reasons.append(reason)

    def as_dict(self) -> dict:
        return {
            "similarity": round(self.similarity, 3),
            "score": self.score,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "details": self.details,
        }


def _shingles(text: str, size: int = 3) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    if len(words) < size:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + size]) for i in range(len(words) - size + 1)}


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def extract_features(html: str, base_url: str = "") -> PageFeatures:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    title = (soup.title.string or "").strip() if soup.title else ""
    text = soup.get_text(" ", strip=True)

    fields = set()
    has_pw = False
    for inp in soup.find_all(["input", "select", "textarea"]):
        name = inp.get("name") or inp.get("id") or ""
        if name:
            fields.add(name.lower())
        if (inp.get("type") or "").lower() == "password":
            has_pw = True

    actions = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        actions.append(urljoin(base_url, action) if base_url else action)

    names, hosts = set(), set()
    # Re-parse because scripts were removed above but their src matters.
    full = BeautifulSoup(html, "html.parser")
    for tag, attr in (("img", "src"), ("script", "src"), ("link", "href"), ("source", "src")):
        for el in full.find_all(tag):
            url = el.get(attr)
            if not url or url.startswith("data:"):
                continue
            absolute = urljoin(base_url, url) if base_url else url
            parsed = urlparse(absolute)
            filename = parsed.path.rsplit("/", 1)[-1].lower()
            if filename:
                names.add(filename)
            if parsed.netloc:
                hosts.add(clean_host(parsed.netloc))

    return PageFeatures(
        title=title,
        text_shingles=_shingles(text),
        form_fields=fields,
        asset_names=names,
        asset_hosts=hosts,
        form_actions=actions,
        has_password_field=has_pw,
    )


def _host_belongs(host: str, brand_host: str) -> bool:
    return host == brand_host or host.endswith("." + brand_host)


def compare_pages(
    reference_html: str,
    suspect_html: str,
    brand_domain: str,
    suspect_url: str = "",
) -> PageFinding:
    """Compare a suspect page to the brand's real page and score it."""
    brand_host = clean_host(brand_domain)
    suspect_host = clean_host(suspect_url) if suspect_url else ""

    ref = extract_features(reference_html, f"https://{brand_host}/")
    sus = extract_features(suspect_html, suspect_url)

    parts = {
        "title": SequenceMatcher(None, ref.title.lower(), sus.title.lower()).ratio() if ref.title else 0.0,
        "text": _jaccard(ref.text_shingles, sus.text_shingles),
        "form_fields": _jaccard(ref.form_fields, sus.form_fields),
        "assets": _jaccard(ref.asset_names, sus.asset_names),
    }
    weights = {"title": 0.2, "text": 0.35, "form_fields": 0.25, "assets": 0.2}
    similarity = sum(parts[k] * weights[k] for k in parts)

    finding = PageFinding(similarity=similarity)
    finding.details["similarity_parts"] = {k: round(v, 3) for k, v in parts.items()}

    hosted_by_brand = bool(suspect_host) and _host_belongs(suspect_host, brand_host)
    if hosted_by_brand:
        finding.reasons.append("Page is served from the protected domain (trusted)")
        return finding

    if similarity >= 0.75:
        finding.add(55, f"Very similar to the real page (similarity {similarity:.0%})")
    elif similarity >= 0.5:
        finding.add(35, f"Similar to the real page (similarity {similarity:.0%})")
    elif similarity >= 0.3:
        finding.add(15, f"Partly similar to the real page (similarity {similarity:.0%})")

    if sus.has_password_field:
        finding.add(10, "Asks for a password")

    # Where do the forms send data?
    off_domain = []
    for action in sus.form_actions:
        if not action:
            continue
        a_host = clean_host(urlparse(action).netloc) if urlparse(action).netloc else suspect_host
        if a_host and not _host_belongs(a_host, brand_host):
            off_domain.append(action)
        if re.search(r"\.(php|cgi|pl)(\?|$)", action, re.I) or action.lower().startswith("mailto:"):
            finding.add(10, f"Form posts to a script or mail handler: {action}")
    if off_domain and finding.score:
        finding.add(20, f"Form submits outside the brand domain: {', '.join(off_domain)}")
    finding.details["form_actions"] = sus.form_actions

    # Lazy clones hot-link the brand's own images and scripts.
    hotlinked = sorted(h for h in sus.asset_hosts if _host_belongs(h, brand_host))
    if hotlinked:
        finding.add(15, f"Loads assets directly from the brand: {', '.join(hotlinked)}")

    # Copied title with the brand's name.
    brand_word = brand_host.split(".")[0]
    if brand_word and brand_word in sus.title.lower():
        finding.add(5, f"Title names the brand: '{sus.title}'")

    return finding
