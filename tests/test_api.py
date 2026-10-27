import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set required env vars BEFORE importing app modules.
# config.py raises RuntimeError if secrets are absent (VT-02 remediation).
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production")
os.environ.setdefault("DB_PASSWORD", "test-only-db-password")
os.environ.setdefault("ADMIN_API_KEY", "test-only-admin-api-key")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402
import models  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


def test_share_scan_without_password():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Shared finding",
        "severity": "high",
        "affected_component": "GET /report",
    }, headers=auth_headers(token)).json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        headers=auth_headers(token),
    )
    assert share_resp.status_code == 200
    share_url = share_resp.json()["share_url"]
    assert share_url.startswith("http://localhost:8000/share/")

    scan_resp = client.get(share_url.removeprefix("http://localhost:8000"))
    assert scan_resp.status_code == 200
    assert scan_resp.json()["title"] == "Shared finding"


def test_share_scan_requires_password_when_configured():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Protected finding",
        "severity": "critical",
        "affected_component": "POST /login",
    }, headers=auth_headers(token)).json()["id"]
    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "stakeholder-secret"},
        headers=auth_headers(token),
    ).json()["share_url"]
    path = share_url.removeprefix("http://localhost:8000")

    assert client.get(path).status_code == 403
    assert client.get(path, params={"password": "wrong-password"}).status_code == 403
    assert client.get(path, params={"password": "x" * 73}).status_code == 403
    response = client.get(path, params={"password": "stakeholder-secret"})
    assert response.status_code == 200
    assert response.json()["title"] == "Protected finding"


def test_share_link_expires_after_24_hours():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Expired finding",
        "severity": "low",
        "affected_component": "worker",
    }, headers=auth_headers(token)).json()["id"]
    share_url = client.post(
        f"/scans/{scan_id}/share",
        headers=auth_headers(token),
    ).json()["share_url"]

    db = TestingSessionLocal()
    try:
        share_link = db.query(models.ShareLink).first()
        assert share_link.expires_at <= datetime.utcnow() + timedelta(hours=24)
        assert share_link.expires_at > datetime.utcnow() + timedelta(hours=23, minutes=59)
        share_link.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    response = client.get(share_url.removeprefix("http://localhost:8000"))
    assert response.status_code == 404


def test_cannot_share_another_users_scan():
    owner_token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Private finding",
        "severity": "medium",
        "affected_component": "worker",
    }, headers=auth_headers(owner_token)).json()["id"]
    other_user_token = register_and_login("bob", "bob@example.com", "secret")

    response = client.post(
        f"/scans/{scan_id}/share",
        headers=auth_headers(other_user_token),
    )
    assert response.status_code == 404


def test_share_nonexistent_scan_returns_404():
    token = register_and_login()
    response = client.post("/scans/99999/share", headers=auth_headers(token))
    assert response.status_code == 404


def test_share_scan_unauthenticated_returns_401():
    response = client.post("/scans/1/share")
    assert response.status_code in (401, 403)


def test_share_invalid_password_returns_422():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Validation finding",
        "severity": "low",
        "affected_component": "worker",
    }, headers=auth_headers(token)).json()["id"]

    # Empty password
    empty_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": ""},
        headers=auth_headers(token),
    )
    assert empty_resp.status_code == 422

    # Password exceeding 72 bytes
    long_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "a" * 73},
        headers=auth_headers(token),
    )
    assert long_resp.status_code == 422


def test_get_share_nonexistent_token_returns_404():
    response = client.get("/share/completely_non_existent_token_12345")
    assert response.status_code == 404


def test_delete_scan_cascades_and_removes_share_link():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Cascade finding",
        "severity": "medium",
        "affected_component": "worker",
    }, headers=auth_headers(token)).json()["id"]

    share_url = client.post(
        f"/scans/{scan_id}/share",
        headers=auth_headers(token),
    ).json()["share_url"]
    path = share_url.removeprefix("http://localhost:8000")

    # Verify link works
    assert client.get(path).status_code == 200

    # Delete scan
    del_resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert del_resp.status_code == 204

    # Share link should now return 404
    assert client.get(path).status_code == 404


def test_search_scans_prevents_sql_injection():
    token = register_and_login()
    # Attempt SQL injection via query parameter
    sqli_payload = "' UNION SELECT 1, 'Injected', 'Injected', 'critical', 'open', 'CVE', 'misc', 1, '2026-01-01' --"
    resp = client.get(f"/scans/search?q={sqli_payload}", headers=auth_headers(token))
    assert resp.status_code == 200
    # Parameterized query should treat the payload as literal string, returning 0 results
    assert len(resp.json()["results"]) == 0


def test_jwt_rejects_none_algorithm():
    # Construct an unverified token with alg: none
    fake_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbGljZSJ9."
    resp = client.get("/scans", headers={"Authorization": f"Bearer {fake_token}"})
    assert resp.status_code == 401


def test_share_scan_rate_limiting_lockout():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Rate Limit finding",
        "severity": "high",
        "affected_component": "api",
    }, headers=auth_headers(token)).json()["id"]

    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "correct-pass"},
        headers=auth_headers(token),
    ).json()["share_url"]
    path = share_url.removeprefix("http://localhost:8000")

    # Send 5 failed attempts
    for _ in range(5):
        client.get(path, params={"password": "wrong-guess"})

    # 6th attempt should be blocked by rate limiter with HTTP 429
    blocked_resp = client.get(path, params={"password": "correct-pass"})
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers


