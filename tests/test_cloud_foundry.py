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
