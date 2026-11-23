"""Configuration loading with sensible defaults, YAML file, and env overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None

DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass
class SMTPConfig:
    host: str = "smtp.example.com"
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_email: str = "security@example.com"
    from_name: str = "IT Security Team"
    timeout: int = 30


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    base_url: str = "http://127.0.0.1:5000"


@dataclass
class DatabaseConfig:
    path: str = "data/phishguard.db"


@dataclass
class Config:
    smtp: SMTPConfig = field(default_factory=SMTPConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    dry_run: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        cfg = cls()
        if "smtp" in data:
            for key, value in data["smtp"].items():
                if hasattr(cfg.smtp, key):
                    setattr(cfg.smtp, key, value)
        if "server" in data:
            for key, value in data["server"].items():
                if hasattr(cfg.server, key):
                    setattr(cfg.server, key, value)
        if "database" in data:
            for key, value in data["database"].items():
                if hasattr(cfg.database, key):
                    setattr(cfg.database, key, value)
        if "dry_run" in data:
            cfg.dry_run = bool(data["dry_run"])
        return cfg

    def apply_env(self) -> "Config":
        """Override SMTP settings from environment variables (keeps secrets out
        of files committed to a repository)."""
        mapping = {
            "PHISHGUARD_SMTP_HOST": ("smtp", "host"),
            "PHISHGUARD_SMTP_PORT": ("smtp", "port"),
            "PHISHGUARD_SMTP_USERNAME": ("smtp", "username"),
            "PHISHGUARD_SMTP_PASSWORD": ("smtp", "password"),
            "PHISHGUARD_SMTP_FROM_EMAIL": ("smtp", "from_email"),
            "PHISHGUARD_SMTP_FROM_NAME": ("smtp", "from_name"),
            "PHISHGUARD_SERVER_BASE_URL": ("server", "base_url"),
            "PHISHGUARD_DATABASE_PATH": ("database", "path"),
        }
        for env_key, (section, attr) in mapping.items():
            value = os.environ.get(env_key)
            if value is None:
                continue
            obj = getattr(self, section)
            if isinstance(getattr(obj, attr), int):
                value = int(value)
            setattr(obj, attr, value)
        return self


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> Config:
    path = Path(path)
    data: Dict[str, Any] = {}
    if path.exists():
        if yaml is None:
            raise RuntimeError("PyYAML is required to load config.yaml")
        with path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
            if isinstance(loaded, dict):
                data = loaded
    return Config.from_dict(data).apply_env()
