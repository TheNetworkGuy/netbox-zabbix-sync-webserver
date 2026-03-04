"""Tests for all FastAPI endpoints.

Covers:
- GET /
- POST /connect_config  (set, update, partial, empty)
- GET  /connect_config  (public values only)
- POST /sync_config     (set, update, empty)
- GET  /sync_config
- DELETE /sync_config/{key}
- POST /sync            (accepted, background task scheduled)
"""
import uuid
from unittest.mock import patch, MagicMock

import pytest


# ── Root ──────────────────────────────────────────────────────────────────────

class TestRoot:

    def test_root_returns_greeting(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["message"] == "Hello from NB-sync-webserver!"


# ── POST /connect_config ─────────────────────────────────────────────────────

class TestPostConnectConfig:

    def test_set_single_value(self, client, store_with_secret):
        resp = client.post("/connect_config", json={"netbox_url": "http://nb:8000"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "netbox_url" in data["updated_keys"]
        # verify persisted
        assert store_with_secret.get_config("netbox_url") == "http://nb:8000"

    def test_set_multiple_values(self, client, store_with_secret):
        payload = {
            "netbox_url": "http://nb",
            "netbox_token": "nbt_abc",
            "zabbix_url": "http://zbx",
            "zabbix_user": "Admin",
            "zabbix_password": "secret",
        }
        resp = client.post("/connect_config", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["updated_keys"]) == 5

    def test_update_existing_value(self, client, store_with_secret):
        client.post("/connect_config", json={"netbox_url": "http://old"})
        client.post("/connect_config", json={"netbox_url": "http://new"})
        assert store_with_secret.get_config("netbox_url") == "http://new"

    def test_empty_payload_returns_info(self, client):
        resp = client.post("/connect_config", json={})
        assert resp.status_code == 200
        assert resp.json()["status"] == "info"

    def test_set_zabbix_token(self, client, store_with_secret):
        resp = client.post("/connect_config", json={"zabbix_token": "zbx_tok_123"})
        assert resp.status_code == 200
        assert store_with_secret.get_config("zabbix_token") == "zbx_tok_123"


# ── GET /connect_config ──────────────────────────────────────────────────────

class TestGetConnectConfig:

    def test_returns_only_public_keys(self, client, store_with_secret):
        store_with_secret.set_config("netbox_url", "http://nb")
        store_with_secret.set_config("netbox_token", "secret_token")
        store_with_secret.set_config("zabbix_url", "http://zbx")
        store_with_secret.set_config("zabbix_user", "Admin")
        store_with_secret.set_config("zabbix_password", "pass")

        resp = client.get("/connect_config")
        assert resp.status_code == 200
        cfg = resp.json()["config"]
        assert "netbox_url" in cfg
        assert "zabbix_url" in cfg
        assert "zabbix_user" in cfg
        # Sensitive keys must NOT be returned
        assert "netbox_token" not in cfg
        assert "zabbix_password" not in cfg

    def test_empty_config(self, client):
        resp = client.get("/connect_config")
        assert resp.status_code == 200
        assert resp.json()["config"] == {}


# ── POST /sync_config ────────────────────────────────────────────────────────

class TestPostSyncConfig:

    def test_set_sync_config(self, client, store_with_secret):
        payload = {"config": {"clustering": "true", "template_cf": "zbx_tpl"}}
        resp = client.post("/sync_config", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert set(data["updated_keys"]) == {"clustering", "template_cf"}

    def test_update_sync_config(self, client, store_with_secret):
        client.post("/sync_config", json={"config": {"clustering": "true"}})
        client.post("/sync_config", json={"config": {"clustering": "false"}})
        assert store_with_secret.get_sync_config("clustering") == "false"

    def test_empty_config_returns_info(self, client):
        resp = client.post("/sync_config", json={"config": {}})
        assert resp.status_code == 200
        assert resp.json()["status"] == "info"

    def test_sync_config_invalidates_instance(self, client, store_with_secret):
        """Updating sync config should invalidate the cached Sync instance."""
        import app.routes as routes
        manager = routes._sync_manager
        # Set up fake cached state
        manager._instance = "fake_instance"
        manager._config_cache = {"old": "val"}

        client.post("/sync_config", json={"config": {"new_key": "val"}})
        assert manager._instance is None
        assert manager._config_cache is None


# ── GET /sync_config ─────────────────────────────────────────────────────────

class TestGetSyncConfig:

    def test_get_sync_config(self, client, store_with_secret):
        store_with_secret.set_sync_config("clustering", "true")
        resp = client.get("/sync_config")
        assert resp.status_code == 200
        assert resp.json()["config"]["clustering"] == "true"

    def test_get_empty_sync_config(self, client):
        resp = client.get("/sync_config")
        assert resp.status_code == 200
        assert resp.json()["config"] == {}


# ── DELETE /sync_config/{key} ────────────────────────────────────────────────

class TestDeleteSyncConfig:

    def test_delete_existing_key(self, client, store_with_secret):
        store_with_secret.set_sync_config("to_delete", "val")
        resp = client.delete("/sync_config/to_delete")
        assert resp.status_code == 200
        assert resp.json()["status"] == "success"
        assert store_with_secret.get_sync_config("to_delete") is None

    def test_delete_nonexistent_key_returns_404(self, client):
        resp = client.delete("/sync_config/nope")
        assert resp.status_code == 404

    def test_delete_invalidates_instance(self, client, store_with_secret):
        import app.routes as routes
        manager = routes._sync_manager
        store_with_secret.set_sync_config("k", "v")
        manager._instance = "fake"
        manager._config_cache = {"k": "v"}

        client.delete("/sync_config/k")
        assert manager._instance is None


# ── POST /sync ───────────────────────────────────────────────────────────────

class TestSyncEndpoint:

    def test_sync_returns_accepted(self, client):
        resp = client.post("/sync", json={"device_filter": {"name": "SW01"}})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["device_filter"] == {"name": "SW01"}

    def test_sync_with_no_filters(self, client):
        resp = client.post("/sync", json={})
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    def test_sync_with_vm_filter(self, client):
        resp = client.post("/sync", json={"vm_filter": {"name": "VM01"}})
        assert resp.status_code == 200
        assert resp.json()["vm_filter"] == {"name": "VM01"}
