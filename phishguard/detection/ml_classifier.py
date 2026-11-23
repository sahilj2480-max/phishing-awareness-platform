"""Optional scikit-learn phishing URL classifier.

This module extracts lexical features from a URL string (no network access,
no external feature service) and trains a logistic-regression model. Training
is run offline via ``python -m phishguard ml train``; the fitted model is
persisted with joblib and used at inference time by ``ml predict`` or the
``analyze url --ml`` flag.

scikit-learn is an *optional* dependency (see ``requirements-ml.txt``). The
module imports it lazily so the rest of PhishGuard runs without it.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .analyzer import BRAND_DOMAINS, SUSPICIOUS_TLDS, URL_SHORTENERS, _is_ip

FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_subdomains",
    "has_ip",
    "uses_https",
    "tld_suspicious",
    "is_shortener",
    "brand_impersonation",
    "has_at_symbol",
    "is_punycode",
    "path_length",
    "num_query_params",
]


def _require_sklearn() -> None:
    try:
        import joblib  # noqa: F401
        import sklearn  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "scikit-learn is required for the ML classifier. "
            "Install it with: pip install -r requirements-ml.txt"
        ) from exc


def extract_features(url: str) -> List[float]:
    """Convert a URL into a fixed-length feature vector (see FEATURE_NAMES)."""
    url = (url or "").strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()

    brand_impersonation = 0
    for brand, official in BRAND_DOMAINS.items():
        if brand in host and official not in host:
            brand_impersonation = 1
            break

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    return [
        float(len(url)),
        float(host.count(".")),
        float(host.count("-")),
        float(sum(c.isdigit() for c in host)),
        float(max(host.count(".") - 1, 0)),
        float(1 if _is_ip(host) else 0),
        float(1 if parsed.scheme == "https" else 0),
        float(1 if tld in SUSPICIOUS_TLDS else 0),
        float(1 if host in URL_SHORTENERS else 0),
        float(brand_impersonation),
        float(1 if "@" in url else 0),
        float(1 if host.startswith("xn--") else 0),
        float(len(parsed.path)),
        float(len(parse_qs(parsed.query))),
    ]


def _load_dataset(csv_path: str) -> List[Dict[str, str]]:
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {csv_path}")
    rows: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or {"url", "label"} - set(reader.fieldnames):
            raise ValueError("dataset CSV must have 'url' and 'label' columns")
        for row in reader:
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip()
            if url and label in {"0", "1"}:
                rows.append({"url": url, "label": label})
    if not rows:
        raise ValueError(f"no usable rows in {csv_path}")
    return rows


def train(csv_path: str, model_path: str, random_state: int = 42) -> Dict[str, Any]:
    """Train a logistic-regression model and persist it to ``model_path``.

    Returns holdout metrics: accuracy, precision, recall, and F1.
    """
    _require_sklearn()
    import joblib
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    rows = _load_dataset(csv_path)
    X = [extract_features(r["url"]) for r in rows]
    y = [int(r["label"]) for r in rows]

    if len(set(y)) < 2:
        raise ValueError("dataset must contain both phishing and benign examples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=random_state, stratify=y
    )
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000))
    model.fit(X_train, y_train)
    preds = model.predict(X_test)

    accuracy = accuracy_score(y_test, preds)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, preds, average="binary", pos_label=1
    )

    model.fit(X, y)
    out = Path(model_path)
    if str(out.parent) and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, str(out))

    return {
        "samples": len(rows),
        "test_size": len(y_test),
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    }


def predict(url: str, model_path: str) -> Dict[str, Any]:
    """Classify a URL using a previously trained model."""
    _require_sklearn()
    import joblib

    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"model not found: {model_path} — train one with: "
            "python -m phishguard ml train"
        )

    model = joblib.load(str(path))
    proba = model.predict_proba([extract_features(url)])[0]
    classes = list(model.classes_)
    phishing_idx = classes.index(1) if 1 in classes else 0
    return {
        "url": url,
        "label": int(classes[int(proba.argmax())]),
        "phishing_probability": float(proba[phishing_idx]),
    }
