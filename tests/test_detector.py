from pathlib import Path

import pytest

from clonephish.cli import main
from clonephish.domains import analyse_domain, levenshtein, normalise, split_domain, to_unicode
from clonephish.pages import compare_pages

BRAND = "mybank.co.za"
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def read(name):
    return (SAMPLES / name).read_text(encoding="utf-8")


# --- helpers ---------------------------------------------------------------

def test_split_domain_handles_multi_part_suffix():
    assert split_domain("login.mybank.co.za") == ("login", "mybank", "co.za")
    assert split_domain("evil.com") == ("", "evil", "com")


def test_levenshtein_counts_transposition_as_one():
    assert levenshtein("mybank", "mybnak") == 1
    assert levenshtein("mybank", "mybank") == 0


def test_normalise_maps_lookalikes():
    assert normalise("myb4nk") == "mybank"
    assert normalise("rnybank") == "mybank"
    assert normalise("mybаnk") == "mybank"  # Cyrillic a


def test_punycode_is_decoded():
    encoded = "mybаnk".encode("punycode").decode()
    assert to_unicode(f"xn--{encoded}.co.za") == "mybаnk.co.za"


# --- domain scoring --------------------------------------------------------

@pytest.mark.parametrize("trusted", ["mybank.co.za", "online.mybank.co.za", "https://mybank.co.za/login"])
def test_real_domain_is_trusted(trusted):
    assert analyse_domain(trusted, BRAND).score == 0


@pytest.mark.parametrize("candidate", [
    "mybnak.co.za",                       # transposition
    "myb4nk.co.za",                       # digit substitution
    "rnybank.co.za",                      # rn -> m
    "mybank-secure-login.com",            # combosquat
    "mybank.co.za.verify-account.net",    # subdomain abuse
])
def test_lookalikes_score_high(candidate):
    finding = analyse_domain(candidate, BRAND)
    assert finding.verdict == "HIGH", finding.reasons


def test_homoglyph_idn_scores_high():
    encoded = "mybаnk".encode("punycode").decode()
    finding = analyse_domain(f"xn--{encoded}.co.za", BRAND)
    assert finding.verdict == "HIGH"
    assert any("Mixes scripts" in r for r in finding.reasons)


def test_tld_swap_is_flagged():
    assert analyse_domain("mybank.com", BRAND).score >= 40


def test_unrelated_domain_is_clean():
    assert analyse_domain("capetownhiking.org.za", BRAND).score == 0


# --- page comparison -------------------------------------------------------

def test_clone_page_scores_high():
    finding = compare_pages(read("reference_login.html"), read("suspect_clone.html"),
                            BRAND, "https://mybank-secure-login.com/")
    assert finding.verdict == "HIGH", finding.reasons
    assert finding.similarity > 0.75
    assert any("outside the brand domain" in r for r in finding.reasons)
    assert any("Loads assets directly" in r for r in finding.reasons)


def test_unrelated_page_scores_low():
    finding = compare_pages(read("reference_login.html"), read("unrelated_page.html"),
                            BRAND, "https://capetownhiking.org.za/")
    assert finding.score < 40
    assert finding.similarity < 0.2


def test_real_page_on_real_domain_is_trusted():
    ref = read("reference_login.html")
    assert compare_pages(ref, ref, BRAND, "https://mybank.co.za/login").score == 0


# --- CT lookup (network mocked) --------------------------------------------

def test_ct_scan_scores_names_from_crtsh(monkeypatch):
    import clonephish.ct as ct

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return [
                {"name_value": "mybank.co.za\nwww.mybank.co.za"},
                {"name_value": "*.mybank-secure-login.com"},
                {"name_value": "mybnak.co.za"},
            ]

    monkeypatch.setattr(ct.requests, "get", lambda *a, **k: FakeResp())
    names = [f.candidate for f in ct.scan_ct(BRAND)]
    assert names[:2] == ["mybank-secure-login.com", "mybnak.co.za"] or set(names) == {"mybank-secure-login.com", "mybnak.co.za"}
    assert "mybank.co.za" not in names


# --- CLI -------------------------------------------------------------------

def test_cli_domains_exit_code(capsys):
    assert main(["domains", "--brand", BRAND, "--no-colour", "mybnak.co.za"]) == 1
    assert main(["domains", "--brand", BRAND, "--no-colour", "capetownhiking.org.za"]) == 0


def test_cli_page_json(capsys):
    code = main(["page", "--brand", BRAND, "--json",
                 "--reference", str(SAMPLES / "reference_login.html"),
                 "--suspect", str(SAMPLES / "suspect_clone.html"),
                 "--suspect-url", "https://mybank-secure-login.com/"])
    out = capsys.readouterr().out
    assert code == 1
    assert '"verdict": "HIGH"' in out
