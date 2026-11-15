# ClonePhish Detector

[![Tests](https://github.com/shuduhadi/clonephish-detector/actions/workflows/tests.yml/badge.svg)](https://github.com/shuduhadi/clonephish-detector/actions/workflows/tests.yml)

A small Python tool that flags **lookalike domains** and **cloned login pages**, the two ingredients of website-cloning phishing. Built as a defensive cybersecurity research project.

> **Use it only for domains and brands you own or are authorised to protect.** It analyses names and saved HTML; it never builds, hosts or submits to phishing pages.

## What it checks

| Command | Question it answers | Signals |
| --- | --- | --- |
| `domains` | Is this domain pretending to be mine? | Typosquats (edit distance), look-alike characters (`4`→`a`, `rn`→`m`), homoglyph/IDN punycode and mixed scripts, combosquats (`brand-secure-login`), brand used as a subdomain, TLD swaps |
| `page` | Is this page a copy of my login page? | Title, text, form-field and asset-name similarity; forms posting off-domain or to scripts; assets hot-linked from the real site; lookalike hosting domain |
| `ct` | Has anyone got a certificate for a lookalike yet? | Searches Certificate Transparency logs via [crt.sh](https://crt.sh) and scores every name found |

Each check returns a **risk score from 0 to 100** with the reasons behind it: `HIGH` (70+), `MEDIUM` (40–69), `LOW` (1–39) or `NONE`.

## Install

```bash
git clone https://github.com/shuduhadi/clonephish-detector.git
cd clonephish-detector
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

All examples use the fictional brand `mybank.co.za` and the files in `samples/`.

**Score candidate domains**

```bash
clonephish domains --brand mybank.co.za mybnak.co.za mybank-secure-login.com
clonephish domains --brand mybank.co.za -f samples/candidates.txt
```

```
mybank.co.za.verify-account.net
  risk: HIGH (90/100)
  - Full brand domain used as a subdomain of 'verify-account.net'
  - Lure words in the registered domain: account, verify
  - Unusually deep subdomain chain
```

**Compare a saved suspect page with your real page**

```bash
clonephish page --brand mybank.co.za \
  --reference samples/reference_login.html \
  --suspect samples/suspect_clone.html \
  --suspect-url https://mybank-secure-login.com/
```

```
risk: HIGH (100/100)
  - Very similar to the real page (similarity 85%)
  - Form submits outside the brand domain: https://collector.example.invalid/next.php
  - Loads assets directly from the brand: www.mybank.co.za
  - Hosted on a lookalike domain (HIGH): mybank-secure-login.com
```

Save suspect pages with `curl -o suspect.html <url>` from an isolated machine or VM rather than opening them in your browser.

**Search Certificate Transparency logs** (needs internet)

```bash
clonephish ct --brand yourdomain.co.za --min-score 40
```

Add `--json` to any command for machine-readable output. Commands exit with code `1` when something scores at or above `--fail-at` (default 70), so the tool can run in a scheduled job or CI pipeline.

## How the scoring works

- **Domains** are cleaned, punycode is decoded, and the registrable name is split from its suffix (`login.mybank.co.za` → `mybank` + `co.za`). Look-alike characters are mapped back to the letters they imitate, then compared with the brand using Damerau-Levenshtein distance.
- **Pages** are compared on four features, weighted: visible text as 3-word shingles (35%), form field names (25%), title (20%) and asset filenames (20%). Similarity is combined with behavioural red flags such as where the form submits.

## Limitations

- The suffix list covers common multi-part suffixes (`co.za`, `co.uk`, …), not the full Public Suffix List.
- Static analysis only: a reverse-proxy (adversary-in-the-middle) phish serves the *real* page, so `page` similarity will be high but asset hot-linking won't show. Domain and CT checks still apply.
- Scores are heuristics for triage, not proof. A human should review anything flagged.

## Run the tests

```bash
pytest -q
```

## Ideas for extending it

- Stream new certificates live from a CT log feed instead of polling crt.sh
- Screenshot comparison (perceptual hashing) to catch visually identical pages with different HTML
- WHOIS / domain-age lookup (new domains are riskier)
- A browser extension that warns before a password is typed on a lookalike domain

## Licence

MIT
