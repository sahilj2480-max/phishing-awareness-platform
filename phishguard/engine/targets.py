"""Target list loading from CSV."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_COLUMNS = {"email"}


def load_targets(path: str | Path) -> List[Dict[str, str]]:
    """Load targets from a CSV file with columns: email, name, department."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"targets file not found: {path}")

    targets: List[Dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
            raise ValueError(f"targets CSV must include an 'email' column (got {reader.fieldnames})")
        for row in reader:
            email = (row.get("email") or "").strip().lower()
            if not email:
                continue
            targets.append(
                {
                    "email": email,
                    "name": (row.get("name") or "").strip(),
                    "department": (row.get("department") or "").strip(),
                }
            )
    return targets


def first_name(name: str) -> str:
    return name.split()[0] if name else "there"


def build_context(target: Dict[str, Any], **overrides: Any) -> Dict[str, str]:
    ctx: Dict[str, str] = {
        "email": target["email"],
        "name": target.get("name", ""),
        "first_name": first_name(target.get("name", "")),
        "department": target.get("department", ""),
    }
    ctx.update({k: str(v) for k, v in overrides.items()})
    return ctx
