# Architecture

PhishGuard is deliberately small and dependency-light. The core is pure Python
(standard library) plus two runtime dependencies: Flask (tracking server) and
PyYAML (configuration).

## Design goals

1. **Safety by default** — sending is a dry-run unless `--send` is explicit.
2. **Explainability** — the detector uses readable rules, not black-box ML.
3. **Testability** — every module is a plain object/function, no global state.
4. **Secrets hygiene** — credentials via env vars, never committed.

## Modules

### `config.py`

`Config` is a set of dataclasses (`SMTPConfig`, `ServerConfig`,
`DatabaseConfig`). `load_config()` merges `config.yaml` with environment
overrides. Keeping config as dataclasses means every consumer gets typed,
validated defaults.

### `storage/store.py`

A thin SQLite wrapper using a per-instance lock. The schema has four tables:

- `targets` — one row per simulated recipient.
- `campaigns` — one row per run.
- `deliveries` — one row per (campaign, target) pair, holding the tracking token.
- `events` — one row per tracked action (`open`, `click`, `submit`, `report`).

Token-to-target resolution is the security boundary: the server never stores or
reads credentials, only counts.

### `engine/`

- `targets.py` — CSV loading and context building.
- `templates.py` — HTML email templates keyed by name, with `{placeholder}`
  rendering.
- `sender.py` — SMTP delivery with a dry-run that logs instead of sending.
- `campaign.py` — mints a unique token per target, renders the email, records a
  delivery, and sends. Returns a summary.

### `landing/app.py`

A Flask app with two kinds of routes: *tracking* (pixel, click redirect) and
*content* (login, training, report). Tracking routes are silent on unknown
tokens so the token namespace cannot be fingerprinted. A `GET /dashboard` route
renders an admin view backed by the store's aggregation helpers.

### `detection/analyzer.py`

A `_Scorer` accumulates `Finding`s with severities; each severity maps to a
weight. The total is capped at 100 and bucketed into `Likely Safe`,
`Suspicious`, or `Likely Phishing`.

### `detection/ml_classifier.py`

An optional scikit-learn classifier. `extract_features()` turns a URL into a
fixed-length lexical vector (length, dots, hyphens, IP flag, HTTPS, suspicious
TLD, shortener, brand impersonation, punycode, and more). `train()` fits a
`StandardScaler` + `LogisticRegression` pipeline, reports holdout
accuracy/precision/recall/F1, and persists the model with joblib; `predict()`
loads it and returns a phishing probability. scikit-learn is imported lazily so
the rest of PhishGuard runs without it.

The heuristic and ML paths are intentionally complementary: the heuristic rules
are fully explainable but only cover patterns they encode, while the ML model
learns decision boundaries from data. Running both (`analyze url --ml`) often
catches URLs the other misses.

### `reporting/report.py`

Pure formatting functions: a `campaign_summary` dict in, `text`/`json`/`csv`/
`html` out. Keeping formatters separate from the store makes them trivially
testable and reusable.

## Data flow

1. `cli.py` parses arguments and loads `Config`.
2. `campaign.send` mints tokens and (in dry-run) logs the email it would send.
3. `server` serves tracking endpoints; each event is appended to `events`.
4. `report` and `/dashboard` aggregate events per campaign and format the result.
5. `ml train` / `ml predict` (and `analyze url --ml`) are independent of the
   campaign pipeline; they read the bundled dataset and a saved model only.
