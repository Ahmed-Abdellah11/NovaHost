# Nova Host – AI Website Classifier

An AI layer for the Nova Host secure network. It watches the DNS queries of the whole network,
classifies every new domain as **SAFE / SUSPICIOUS / BLOCK**, and keeps the DNS server's blocklist
up to date automatically – no manual lists.

```
 PCs (VLANs) ──DNS──►  ┌─────────── nova-ai-dns container ───────────┐ ──► Internet DNS
                       │ dnsmasq ──query log──► nova.watcher         │
                       │    ▲                      │ classify        │
                       │    └──── blocklist ◄──────┤                 │
                       │          (SIGHUP)    ┌────▼─────────────┐   │
                       │                      │ Decision engine  │   │
 Admin ──browser──►    │  FastAPI :8000       │ 1 admin override │   │
   dashboard / API     │  (dashboard, REST)   │ 2 allowlist      │   │
                       │        │             │ 3 denylist       │   │
                       │        └──► SQLite   │ 4 known-bad feed │   │
                       │                      │ 5 ML model       │   │
                       └──────────────────────┴──────────────────┴───┘
```

| Verdict | Meaning | What happens |
|---|---|---|
| `SAFE` | looks normal | resolves normally |
| `SUSPICIOUS` | in the grey zone | **not blocked**; goes to the admin review queue (Allow / Block buttons) |
| `BLOCK` | very likely malicious | DNS answers `0.0.0.0` |

## Quick start (no Docker)

```bash
pip install -r requirements.txt
python -m nova.data        # download public lists -> data/dataset.csv.gz   (already included)
python -m nova.train       # train + evaluate -> models/model.joblib, reports/*.png, metrics.json
python -m nova.feeds       # refresh the known-bad feed -> models/feed.txt.gz
python -m pytest -q tests  # 10 tests
uvicorn nova.api:app --port 8000   # dashboard: http://localhost:8000   API docs: /docs
```
Try it: `curl -X POST localhost:8000/classify -H 'Content-Type: application/json' -d '{"domain":"paypal-secure-login.xyz"}'`

## Deployment (Docker)

```bash
docker compose up --build -d
dig @127.0.0.1 google.com            # use -p 5353 if you mapped 5353:53
open http://localhost:8000           # dashboard
```
One container runs dnsmasq + the watcher + the API, so it can be dropped into GNS3 as a single node
(see [docs/GNS3.md](docs/GNS3.md)). Set `NOVA_API_KEY` – `/allow` and `/deny` require the `X-API-Key` header.

## REST API

| Method | Path | Purpose |
|---|---|---|
| POST | `/classify` `{"domain": "..."}` | verdict + score + reasons (dry run; add `?record=true` to log it) |
| POST | `/classify/batch` | up to 1000 domains |
| GET | `/review` | suspicious domains waiting for a decision |
| GET | `/decisions`, `/stats` | recent decisions, counters |
| POST | `/allow`, `/deny` | admin override (needs `X-API-Key` if set) – blocklist reloads instantly |
| GET | `/blocklist` | the live blocklist (hosts format) |
| GET | `/health` | model version, thresholds, feed size |

## Data

All public, GitHub-hosted lists (downloaded by `nova.data`, nothing is scraped):

| Class | Source | Used |
|---|---|---|
| Benign | zer0h/top-1000000-domains (top 100k) + opendns/public-domain-lists | 70,000 |
| Malicious | mitchellkrogza/Phishing.Database (active phishing domains) | 55,000 |
| Malicious | StevenBlack/hosts (malware / ad / tracker domains) | 15,000 |

Cleaning: normalised, validated, de-duplicated; malicious entries whose registered domain is also in
the popular-sites list are dropped (label noise); 35 % of benign names get a common subdomain prefix
(`www`, `mail`, `login`, …) so that "has a subdomain" or "contains login" is not a free shortcut.

## Model

* **A – Gradient boosting** on 20 hand-crafted lexical features (length, entropy, hyphens, digit ratio,
  suspicious keywords/TLD, brand impersonation, IP host, punycode, …).
* **B – Logistic regression** on TF-IDF character n-grams (2–4).
* **Ensemble** – weighted average (weight chosen on validation data).
* **Thresholds** are chosen on a validation set, never on test data: `BLOCK` = 0.5 % false-positive
  rate, `SUSPICIOUS` = 3 %.
* Split is **grouped by registered domain** (70/10/20) so the same site can't appear in train and test.
* Every non-safe verdict comes with human-readable **reasons** (keywords, brand impersonation, random-looking name…).

### Results (held-out test set, 26,588 domains)

| | AUC |
|---|---|
| Gradient boosting | 0.889 |
| Char n-gram LR | 0.944 |
| **Ensemble** | **0.946** |

| Threshold | Precision | Recall | False-positive rate |
|---|---|---|---|
| BLOCK (0.81) | 99.1 % | 60.0 % | 0.52 % |
| SUSPICIOUS+ (0.64) | 95.9 % | 74.1 % | 2.91 % |

Recall at BLOCK: phishing 64.9 %, tracker/malware hosts 44.6 %. Plots: `reports/` (ROC, confusion matrix,
score distribution, feature importance).

### Honest limitations

* **It reads the name only**, not the page. Lexical detection has a ceiling – that is why it is one layer
  next to ACLs / WAF / the threat feed, not a replacement.
* **Benign training data = popular sites.** Long-tail names (small businesses, schools) can score higher than
  they should. Example: `cairo-hospital.org` → SUSPICIOUS. That is exactly why grey-zone domains are *reviewed,
  not blocked*, and why you can retrain on your own traffic (below).
* **Precision above is on a ~50/50 test set.** In real traffic malicious domains are rare, so real precision is
  lower; the false-positive *rate* is the number to trust.
* **Reactive:** a never-seen domain's first lookup is answered before the AI classifies it; later lookups are blocked.
  The known-bad feed (362k domains) covers domains already reported by others.
* DNS filtering is bypassed by DNS-over-HTTPS or hard-coded resolvers – force clients to the AI DNS server with an ACL
  and disable browser DoH (see docs/GNS3.md).
* Not tested here: the Docker image build and GNS3 import (see "What was verified" below).

### Retrain on your own network (recommended)

```bash
python -m nova.export_local   # domains your users really visit and the AI judged SAFE -> data/local_benign.txt
python -m nova.data && python -m nova.train
```

## What was verified

* 10 unit/API tests pass (`pytest`).
* End-to-end on a **real dnsmasq**: first lookup of a phishing / random-looking domain resolved, the watcher classified
  it from the query log, rewrote the blocklist, signalled dnsmasq (SIGHUP), and the second lookup returned `0.0.0.0`;
  normal sites stayed reachable and a grey-zone domain was left unblocked.
* **Not run in the build environment:** `docker build` and GNS3 import – follow docs/GNS3.md and report any problem.

## Layout

```
nova/        features.py data.py train.py predict.py feeds.py store.py service.py
             watcher.py blocklist.py api.py export_local.py config.py
models/      model.joblib (1.6 MB)  feed.txt.gz (3.2 MB)
reports/     metrics.json + PNG charts for the report
config/      allowlist.txt  denylist.txt
docker/      entrypoint.sh  dnsmasq.conf        Dockerfile  docker-compose.yml
docs/        GNS3.md  DEMO.md  REPORT_SNIPPETS.md
```
