# PhishGuard

Phishing URL detector using a Random Forest classifier backed by real-time threat intelligence APIs and rule-based heuristics. Built with Flask.

---

## Background

Most phishing detectors either rely purely on a blocklist (which misses new domains) or purely on ML (which has too many false positives on its own). PhishGuard runs both in parallel and uses a weighted flag system to make the final call — no single signal decides the verdict.

---

## Detection pipeline

Every URL goes through the following checks in order:

**1. Whitelist** — major known-safe domains are cleared immediately without hitting any API.

**2. Private IP check** — URLs pointing to private IP ranges are flagged immediately. Legitimate public URLs don't use private IPs.

**3. Google Safe Browsing** — real-time query against Google's threat database. A hit adds 2 flags.

**4. VirusTotal** — submits the URL and reads scan results from 90+ engines. 2+ engines flagging = 2 flags. 1 engine = 1 flag (low risk warning).

**5. WHOIS** — checks domain registration age. Domains under 180 days old get flagged — phishing campaigns almost always use freshly registered domains.

**6. ML model** — Random Forest trained on 88k URLs with 111 structural features extracted from the URL itself. Adds 1 flag if it predicts phishing.

**7. Brand spoof check** — rule-based check for domains that contain brand keywords without being the actual brand domain. Catches zero-day brand impersonation that APIs haven't seen yet.

Final verdict:
- Any hard flag from GSB, VT, or brand spoof → **PHISHING**
- ML confidence > 60% with unknown domain age → **PHISHING**
- 3 or more soft flags total → **PHISHING**
- Otherwise → **SAFE**

---

## ML model

**Algorithm:** Random Forest — 200 trees, max depth 20, min samples per leaf 5

**Training data:** 88,647 URLs augmented with 5,000 synthetic brand-spoof samples generated to fill a gap in the original dataset (bare-domain phishing URLs were underrepresented).

**Features (111 total):** Character-level counts across four URL segments — full URL, domain, directory, file, and query params. Includes counts of dots, hyphens, slashes, special characters, digits, vowels, subdomain depth, TLD presence in params, email pattern detection, and network signals like domain age, MX record count, nameserver count, and TTL.

**Note:** Early versions included `has_https` as a feature. The training dataset stored most benign URLs without the `https://` prefix, so the model learned HTTP = phishing. Removing it and normalizing all URLs before feature extraction fixed the false positive rate significantly.

**Accuracy:** 96.28% on a stratified 80/20 split.

---

## Stack

- Python, Flask
- scikit-learn (Random Forest)
- Google Safe Browsing API v4
- VirusTotal API v3
- python-whois, dnspython, tldextract
- python-dotenv

---

## Limitations

**Zero-day domains** — if a phishing domain was registered today and hasn't been reported to VT or GSB yet, the API checks won't catch it. The brand spoof check and ML model partially cover this but not completely.

**VirusTotal rate limit** — free tier is capped at 4 requests/minute. Under load, VT checks may time out.

**WHOIS reliability** — privacy-protected domains often return no registration date. The app treats unknown age as a weak warning rather than a hard flag to avoid over-flagging.

**Short bare-domain phishing** — URLs like `evil-paypal.com` with no path have almost identical structural features to legitimate short domains. The model alone can't reliably separate them — the brand spoof rule handles most of these cases.

---

## Project structure

```
phisguard/
├── app.py
├── phishguard_model.pkl
├── phishing_full.csv
├── malicious_phish.csv
├── phisguard.ipynb
├── templates/
│   └── index.html
└── .env              # API keys — not committed
```

---

*Muhammad Siddhiq J — B.E. Cyber Security, SRMVEC*
