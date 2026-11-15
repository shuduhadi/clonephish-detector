"""Lookalike-domain analysis.

Scores a candidate domain against a protected brand domain using signals that
map to common phishing naming tricks: typosquatting, character substitution,
homoglyph / IDN spoofing, combosquatting, subdomain abuse and TLD swaps.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

# Multi-label public suffixes we care about. Not a full Public Suffix List,
# but enough for common cases (especially South African and UK domains).
MULTI_PART_SUFFIXES = {
    "co.za", "org.za", "gov.za", "ac.za", "net.za", "web.za", "edu.za",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.in", "com.br", "co.jp",
    "com.ng", "co.ke", "com.na", "co.bw",
}

# Characters that are commonly swapped in for look-alikes. Mapped to the
# letter they imitate. Includes digits, multi-char tricks and common
# Cyrillic / Greek homoglyphs.
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "ԁ": "d", "ԛ": "q", "ѕ": "s", "ɡ": "g",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i",
    "ı": "i", "ӏ": "l",
}
MULTI_CHAR_LOOKALIKES = {"rn": "m", "vv": "w", "cl": "d"}

# Words attackers bolt onto a brand to make a URL look official.
LURE_WORDS = {
    "login", "signin", "sign-in", "secure", "security", "verify", "verification",
    "account", "update", "support", "help", "auth", "online", "banking",
    "wallet", "billing", "payment", "confirm", "service", "portal", "mfa",
}


@dataclass
class DomainFinding:
    candidate: str
    brand: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)

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
            "candidate": self.candidate,
            "brand": self.brand,
            "score": self.score,
            "verdict": self.verdict,
            "reasons": self.reasons,
        }


def clean_host(value: str) -> str:
    """Strip scheme, path, port and trailing dot; lowercase."""
    host = value.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]  # drop user:pass@
    host = host.split(":", 1)[0]
    return host.rstrip(".").lower()


def to_unicode(host: str) -> str:
    """Decode punycode (xn--) labels to Unicode for analysis."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def split_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomains, registrable label, suffix).

    'login.mybank.co.za' -> ('login', 'mybank', 'co.za')
    """
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        suffix = ".".join(parts[-2:])
        rest = parts[:-2]
    elif len(parts) >= 2:
        suffix = parts[-1]
        rest = parts[:-1]
    else:
        return "", host, ""
    label = rest[-1] if rest else ""
    subs = ".".join(rest[:-1])
    return subs, label, suffix


def scripts_in(text: str) -> set[str]:
    """Rough Unicode script detection using character names."""
    found = set()
    for ch in text:
        if ch in "-.0123456789":
            continue
        try:
            found.add(unicodedata.name(ch).split(" ")[0])
        except ValueError:
            found.add("UNKNOWN")
    return found


def normalise(label: str) -> str:
    """Map look-alike characters back to the letters they imitate."""
    out = "".join(HOMOGLYPHS.get(ch, ch) for ch in label)
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    for fake, real in MULTI_CHAR_LOOKALIKES.items():
        out = out.replace(fake, real)
    return out


def levenshtein(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def analyse_domain(candidate: str, brand: str) -> DomainFinding:
    """Score how likely `candidate` is a lookalike of `brand`."""
    raw = clean_host(candidate)
    brand_host = clean_host(brand)
    finding = DomainFinding(candidate=raw, brand=brand_host)

    host = to_unicode(raw)
    b_subs, b_label, b_suffix = split_domain(brand_host)
    c_subs, c_label, c_suffix = split_domain(host)

    # The brand's own domain and its subdomains are trusted.
    if host == brand_host or host.endswith("." + brand_host):
        finding.reasons.append("Matches the protected domain (trusted)")
        return finding

    if raw != host:
        finding.add(15, f"Uses punycode/IDN; displays as '{host}'")

    scripts = scripts_in(c_label)
    if len(scripts) > 1:
        finding.add(35, f"Mixes scripts in one label: {', '.join(sorted(scripts))}")
    elif scripts and scripts != {"LATIN"}:
        finding.add(15, f"Uses non-Latin script: {', '.join(sorted(scripts))}")

    norm_label = normalise(c_label)
    norm_brand = normalise(b_label)

    if c_label == b_label and c_suffix != b_suffix:
        finding.add(60, f"Same name under a different suffix (.{c_suffix} vs .{b_suffix})")
    elif norm_label == norm_brand and c_label != b_label:
        finding.add(75, f"Look-alike characters: '{c_label}' normalises to '{norm_brand}'")
    else:
        dist = levenshtein(norm_label, norm_brand)
        if 0 < dist <= 2 and len(b_label) >= 4:
            finding.add(70 if dist == 1 else 50, f"Typosquat: edit distance {dist} from '{b_label}'")

    # Combosquatting: brand inside a longer registrable label.
    tokens = set(norm_label.replace("_", "-").split("-"))
    if b_label and b_label in norm_label and norm_label != norm_brand:
        lures = sorted(tokens & LURE_WORDS)
        if lures:
            finding.add(70, f"Combosquat: brand plus lure word(s) {', '.join(lures)}")
        else:
            finding.add(45, f"Brand name '{b_label}' embedded in '{c_label}'")

    # Subdomain abuse: brand sits left of someone else's registered domain.
    if c_subs and (brand_host in c_subs):
        finding.add(70, f"Full brand domain used as a subdomain of '{c_label}.{c_suffix}'")
    elif c_subs and b_label in c_subs.split("."):
        finding.add(55, f"Brand appears only as a subdomain of '{c_label}.{c_suffix}'")
    label_lures = sorted(set(c_label.split("-")) & LURE_WORDS)
    if finding.score and label_lures and b_label not in norm_label:
        finding.add(15, f"Lure words in the registered domain: {', '.join(label_lures)}")

    # A few cheap extra hints.
    sub_tokens = set(c_subs.replace(".", "-").split("-")) if c_subs else set()
    if finding.score and (sub_tokens & LURE_WORDS):
        finding.add(10, f"Lure words in subdomain: {', '.join(sorted(sub_tokens & LURE_WORDS))}")
    if host.count(".") >= 4:
        finding.add(5, "Unusually deep subdomain chain")

    return finding
