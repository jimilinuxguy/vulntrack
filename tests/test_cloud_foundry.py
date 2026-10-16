import json
import pytest
from app.db import cloud_database_url

def test_vcap_postgres_credentials(monkeypatch):
    monkeypatch.setenv("VCAP_SERVICES", json.dumps({"aws-rds": [{"label": "aws-rds", "credentials": {
        "host": "db.example", "username": "demo", "password": "p@ss", "name": "demo"}}]}))
    url = cloud_database_url()
    assert "postgresql+psycopg://" in url
    assert "p%40ss" in url
    assert "sslmode=require" in url

def test_vcap_uri(monkeypatch):
    monkeypatch.setenv("VCAP_SERVICES", json.dumps({"postgres": [{"credentials": {"uri": "postgres://user:pass@host/db"}}]}))
    assert cloud_database_url() == "postgresql+psycopg://user:pass@host/db?sslmode=require"

def test_vcap_invalid(monkeypatch):
    monkeypatch.setenv("VCAP_SERVICES", "not json")
    with pytest.raises(RuntimeError):
        cloud_database_url()


def test_demo_sqlite_without_rds(monkeypatch):
    from app import db
    monkeypatch.setattr(db.settings, "demo_mode", True)
    monkeypatch.setattr(db.settings, "cloud_foundry", True)
    monkeypatch.setattr(db.settings, "dev_auth", False)
    monkeypatch.delenv("VCAP_SERVICES", raising=False)
    assert db.resolve_database_url() == "sqlite:////tmp/vulntrack-demo.db"

def test_demo_rejects_dev_auth(monkeypatch):
    from app import db
    monkeypatch.setattr(db.settings, "demo_mode", True)
    monkeypatch.setattr(db.settings, "dev_auth", True)
    with pytest.raises(RuntimeError, match="Development authentication"):
        db.resolve_database_url()

def test_demo_requires_cloud_foundry(monkeypatch):
    from app import db
    monkeypatch.setattr(db.settings, "demo_mode", True)
    monkeypatch.setattr(db.settings, "cloud_foundry", False)
    monkeypatch.setattr(db.settings, "dev_auth", False)
    monkeypatch.delenv("VCAP_APPLICATION", raising=False)
    with pytest.raises(RuntimeError, match="requires Cloud Foundry"):
        db.resolve_database_url()
