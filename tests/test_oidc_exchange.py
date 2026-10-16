from fastapi.testclient import TestClient
from app.main import app


def test_oidc_exchange_requires_configuration(monkeypatch):
    monkeypatch.delenv("VULNTRACK_OIDC_TOKEN_URL", raising=False)
    with TestClient(app) as client:
        response = client.post("/api/auth/token", data={
            "grant_type": "authorization_code",
            "code": "example",
            "client_id": "vulntrack",
            "redirect_uri": "https://vulntrack-sandbox.app.cloud.gov/",
            "code_verifier": "a" * 43,
        })
    assert response.status_code == 503


def test_oidc_exchange_rejects_unregistered_redirect(monkeypatch):
    monkeypatch.setenv("VULNTRACK_OIDC_TOKEN_URL", "https://id.example.gov/token")
    monkeypatch.setenv("VULNTRACK_OIDC_ISSUER", "https://id.example.gov")
    monkeypatch.setenv("VULNTRACK_OIDC_CLIENT_ID", "vulntrack")
    monkeypatch.setenv("VULNTRACK_OIDC_REDIRECT_URI", "https://vulntrack-sandbox.app.cloud.gov/")
    with TestClient(app) as client:
        response = client.post("/api/auth/token", data={
            "grant_type": "authorization_code",
            "code": "example",
            "client_id": "vulntrack",
            "redirect_uri": "https://attacker.example/",
            "code_verifier": "a" * 43,
        })
    assert response.status_code == 400


def test_oidc_exchange_rejects_foreign_token_host(monkeypatch):
    monkeypatch.setenv("VULNTRACK_OIDC_TOKEN_URL", "https://other.example.gov/token")
    monkeypatch.setenv("VULNTRACK_OIDC_ISSUER", "https://id.example.gov")
    monkeypatch.setenv("VULNTRACK_OIDC_CLIENT_ID", "vulntrack")
    monkeypatch.setenv("VULNTRACK_OIDC_REDIRECT_URI", "https://vulntrack-sandbox.app.cloud.gov/")
    with TestClient(app) as client:
        response = client.post("/api/auth/token", data={
            "grant_type": "authorization_code",
            "code": "example",
            "client_id": "vulntrack",
            "redirect_uri": "https://vulntrack-sandbox.app.cloud.gov/",
            "code_verifier": "a" * 43,
        })
    assert response.status_code == 503
