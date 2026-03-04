"""Shared fixtures for the test suite."""
import hashlib
import hmac
import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from token_store import SecretStore


# ---------------------------------------------------------------------------
# Isolation: every test gets its own temporary DB + encryption key
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """Point DB and encryption key to a temp directory for every test."""
    db_path = str(tmp_path / "test_secrets.db")
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("WEBHOOK_DB_PATH", db_path)
    monkeypatch.setenv("CONNECT_CONFIG_ENCRYPTION_KEY", key)


@pytest.fixture()
def store(tmp_path):
    """Return a fresh, initialised SecretStore backed by a temp DB."""
    db_path = str(tmp_path / "test_secrets.db")
    key = Fernet.generate_key().decode()
    os.environ["CONNECT_CONFIG_ENCRYPTION_KEY"] = key
    s = SecretStore(db_path=db_path)
    s.initialize()
    return s


@pytest.fixture()
def store_with_secret(store):
    """A SecretStore that already has a webhook secret generated."""
    store.generate_and_store_secret()
    return store


# ---------------------------------------------------------------------------
# FastAPI TestClient with security dependency overridden
# ---------------------------------------------------------------------------

def _make_security_override():
    """Return a dependency that always passes security checks."""
    async def _override():
        return {
            "client_ip": "127.0.0.1",
            "event_id": str(uuid.uuid4()),
            "timestamp": str(int(time.time())),
            "valid": True,
        }
    return _override


@pytest.fixture()
def client(store_with_secret, monkeypatch):
    """
    FastAPI TestClient with:
    - security dependency bypassed
    - Sync class mocked (no real NetBox/Zabbix needed)
    - module-level caches reset between tests
    """
    # Reset module-level caches before importing app
    import main as main_mod
    main_mod._sync_instance = None
    main_mod._sync_config_cache = None
    main_mod._sync_connection_cache = None

    # Patch the module-level `store` used everywhere in main
    monkeypatch.setattr(main_mod, "store", store_with_secret)

    # Bypass webhook security
    from middleware import webhook_security_dependency
    main_mod.app.dependency_overrides[webhook_security_dependency] = _make_security_override()

    with TestClient(main_mod.app) as tc:
        yield tc

    main_mod.app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Helpers for signed requests (used by integration / security tests)
# ---------------------------------------------------------------------------

def sign_request(payload: dict, secret: str, event_id: str | None = None):
    """Build headers + body for a properly signed webhook request."""
    if event_id is None:
        event_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    body = json.dumps(payload, separators=(",", ":")).encode()
    message = f"{timestamp}.{body.decode()}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": event_id,
    }
    return headers, body
