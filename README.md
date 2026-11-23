# PhishGuard

Authorized phishing simulation and security awareness training platform.

PhishGuard lets a security team run **controlled, consent-based** phishing
simulations to measure and improve employee security awareness. It is a small,
readable Python project that demonstrates solid fundamentals across the full
cycle: campaign planning, SMTP delivery, tracking, credential-capture
simulation, heuristic detection, and reporting — while keeping an explicit
focus on ethics and authorized use.

> **Intended use:** security awareness training **within your own
> organization, with explicit authorization**. See [Ethics & Legal](#ethics--legal).

## Why this project

Most companies care about information security, but "security" is as much a
**people** problem as a technical one. PhishGuard connects the two:

| Side | What it does | Demonstrates |
|------|--------------|--------------|
| Offense (simulation) | Sends realistic phishing emails and captures who falls for them | SMTP, tracking tokens, web tracking, campaign metrics |
| Defense (detection) | Scores emails/URLs for phishing indicators with *explainable* rules | Heuristic analysis, email header forensics |
| Awareness (education) | Trains users *at the moment of failure* | Behavior change, positive reinforcement |

## Features

- **Campaign engine** — per-target tracking tokens, HTML email templates
  (password reset, invoice, HR policy), and a **dry-run safety default** so a
  simulation can never email a real person accidentally.
- **Tracking & landing server** (Flask) — open-tracking pixel, click tracking,
  a simulated credential page, and instant "you clicked a phish" training.
- **Heuristic analyzer** — an explainable phishing detector (no black-box ML)
  that flags IP-based URLs, URL shorteners, brand impersonation, homographs,
  suspicious TLDs, urgency language, SPF/DKIM/DMARC failures, and risky
  attachments.
- **Reporting** — delivered/opened/clicked/submitted/reported metrics, a
  per-department breakdown, and text/JSON/CSV/HTML output.
- **Secrets hygiene** — SMTP credentials via environment variables, so nothing
  sensitive is ever committed.

## Quick start

```bash
# 1. Create a virtual environment and install
python -m venv .venv
# Windows:  .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# 2. Generate example config + targets
python -m phishguard init

# 3. (Optional) run the analyzer on a suspicious URL — no setup needed
python -m phishguard analyze url "http://paypal.secure-login.com/verify"

# 4. Run a campaign in DRY-RUN (sends nothing — logs what it would send)
python -m phishguard campaign send \
  --name demo --template password_reset --targets data/targets.example.csv

# 5. Start the tracking/landing server
python -m phishguard server

# 6. Generate a report for a campaign
python -m phishguard report 1 --format text
python -m phishguard report 1 --format html   # writes report_1.html
```

### Sending real email (optional, authorized use only)

1. Edit `config.yaml` (or set `PHISHGUARD_SMTP_*` env vars) with your SMTP host
   and credentials.
2. Add the `--send` flag to bypass dry-run:

```bash
python -m phishguard campaign send \
  --name q3-audit --template invoice --targets data/targets.csv --send
```

## CLI reference

```
python -m phishguard <command>

init                                create example config.yaml + targets file
analyze url <url>                   score a URL for phishing indicators
analyze email <file.eml>            score a raw email (.eml) for phishing indicators
campaign send --name N --template T --targets F [--send]
campaign list                       list campaigns
server [--debug]                    run the tracking/landing server
report <id> [--format text|json|csv|html]
```

## Architecture

```
                         ┌──────────────────────────────┐
   targets.csv ─────────▶│  engine/campaign.py          │
                         │  (tokens, render, deliver)    │
                         └──────────────┬───────────────┘
                                        │ SMTP (or dry-run log)
                                        ▼
                        ┌───────────────────────────────┐
                        │        user's inbox            │
                        └──────┬───────────────┬────────┘
                         opens │               │ clicks
                               ▼               ▼
                        ┌────────────────────────────────────┐
                        │  landing/app.py (Flask)            │
                        │  /t/:token  pixel (open)           │
                        │  /c/:token  redirect (click)       │
                        │  /landing/:token  login page       │
                        │  /submit/:token   capture          │
                        │  /report/:token   good catch!      │
                        └───────────────┬────────────────────┘
                                        ▼
                        ┌────────────────────────────────────┐
                        │  storage/store.py (SQLite)         │
                        │  targets, campaigns, deliveries,   │
                        │  events (open/click/submit/report) │
                        └───────────────┬────────────────────┘
                                        ▼
                        ┌────────────────────────────────────┐
                        │  reporting/report.py               │
                        │  text / json / csv / html          │
                        └────────────────────────────────────┘

   (independent)  detection/analyzer.py  →  explainable phishing scoring
```

## Project structure

```
phishguard/
├── phishguard/
│   ├── __main__.py            # python -m phishguard entry point
│   ├── cli.py                 # argument parsing + command handlers
│   ├── config.py              # dataclass config + YAML + env overrides
│   ├── engine/                # targets, templates, sender, campaign
│   ├── landing/               # Flask tracking/landing server
│   ├── detection/             # heuristic analyzer
│   ├── reporting/             # metrics + report formatters
│   └── storage/               # SQLite persistence
├── data/targets.example.csv
├── tests/
├── docs/architecture.md
├── requirements.txt
└── LICENSE
```

## Configuration

Settings live in `config.yaml` (generated by `init`). Secrets should be set via
environment variables, which override the file:

| Variable | Meaning |
|----------|---------|
| `PHISHGUARD_SMTP_HOST` | SMTP server host |
| `PHISHGUARD_SMTP_PORT` | SMTP port |
| `PHISHGUARD_SMTP_USERNAME` | SMTP username |
| `PHISHGUARD_SMTP_PASSWORD` | SMTP password |
| `PHISHGUARD_SMTP_FROM_EMAIL` | From address |
| `PHISHGUARD_SMTP_FROM_NAME` | From display name |
| `PHISHGUARD_SERVER_BASE_URL` | Public URL of the tracking server |
| `PHISHGUARD_DATABASE_PATH` | SQLite database path |

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

## Ethics & Legal

PhishGuard is a **training and research tool**. It must be used only for
security awareness training that you are **explicitly authorized** to conduct,
typically within your own organization. Do not use it to:

- phish people without their organization's authorization,
- collect or store real credentials (the landing page **discards** submitted
  values — it records only that a submission happened),
- target third parties, or impersonate brands without permission.

Unauthorized phishing, even for "education," may violate computer-fraud and
privacy laws. Use responsibly.

## Roadmap ideas

- Template scheduler (send at staggered times to avoid bulk-detection).
- ML URL classifier alongside the heuristic rules (for a more advanced demo).
- REST API and a small dashboard frontend.
- Integration with a real mail relay and DMARC reporting.

## License

MIT — see [LICENSE](LICENSE).
