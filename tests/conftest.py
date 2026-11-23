"""Shared pytest fixtures."""

import pytest

from phishguard.config import Config, SMTPConfig, ServerConfig, DatabaseConfig


@pytest.fixture
def cfg(tmp_path) -> Config:
    return Config(
        smtp=SMTPConfig(from_email="security@example.com", from_name="IT Security"),
        server=ServerConfig(base_url="http://127.0.0.1:5000"),
        database=DatabaseConfig(path=str(tmp_path / "test.db")),
        dry_run=True,
    )


@pytest.fixture
def targets_csv(tmp_path):
    path = tmp_path / "targets.csv"
    path.write_text(
        "email,name,department\n"
        "alice@example.com,Alice Smith,Finance\n"
        "bob@example.com,Bob Jones,Engineering\n",
        encoding="utf-8",
    )
    return str(path)
