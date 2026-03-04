"""Tests for the SecretStore / token_store module.

Covers:
- DB creation from scratch
- Webhook secret lifecycle (generate, read, cache)
- Encrypted connection config CRUD
- Plain-text sync config CRUD
"""
import os
from pathlib import Path

import pytest

from app.token_store import SecretStore, SecretStoreError


# ── 1. Database creation ─────────────────────────────────────────────────────

class TestDatabaseCreation:

    def test_initialize_creates_db_file(self, tmp_path):
        """Running initialize() on a fresh path must create the DB file."""
        db_path = str(tmp_path / "subdir" / "new.db")
        s = SecretStore(db_path=db_path)
        s.initialize()
        assert Path(db_path).exists()

    def test_initialize_creates_tables(self, store):
        """All expected tables should be present after initialize()."""
        import sqlite3
        conn = sqlite3.connect(store.db_path)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert "webhook_secrets" in tables
        assert "connection_config" in tables
        assert "sync_config" in tables

    def test_double_initialize_is_safe(self, store):
        """Calling initialize() twice should not raise."""
        store.initialize()  # second call


# ── 2. Webhook secret lifecycle ──────────────────────────────────────────────

class TestWebhookSecret:

    def test_no_secret_initially(self, store):
        """A freshly initialized store has no secret."""
        assert store.get_latest_secret() is None
        assert store.get_cached_secret() is None

    def test_generate_and_store_secret(self, store):
        """generate_and_store_secret() should return a non-empty string."""
        secret = store.generate_and_store_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_get_latest_secret(self, store):
        """After storing, get_latest_secret() returns the same value."""
        secret = store.generate_and_store_secret()
        assert store.get_latest_secret() == secret

    def test_cached_secret_returns_same_value(self, store):
        """get_cached_secret() caches and returns the stored secret."""
        secret = store.generate_and_store_secret()
        assert store.get_cached_secret() == secret
        # Second call should use the cache
        assert store.get_cached_secret() == secret

    def test_refresh_cache_picks_up_new_secret(self, store):
        """refresh_cache() should pick up a newly stored secret."""
        first = store.generate_and_store_secret()
        assert store.get_cached_secret() == first

        # Manually insert a second secret without going through
        # generate_and_store_secret (which updates the cache itself).
        import sqlite3
        from datetime import datetime, timezone
        conn = sqlite3.connect(store.db_path)
        conn.execute(
            "INSERT INTO webhook_secrets (secret, created_at) VALUES (?, ?)",
            ("manual_secret", datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()

        # Cache still holds 'first' until explicitly refreshed
        assert store.get_cached_secret() == first
        store.refresh_cache()
        assert store.get_cached_secret() == "manual_secret"

    def test_multiple_secrets_returns_latest(self, store):
        """With multiple secrets, get_latest_secret returns the most recent."""
        store.generate_and_store_secret()
        second = store.generate_and_store_secret()
        assert store.get_latest_secret() == second


# ── 3. Connection config (encrypted) ────────────────────────────────────────

class TestConnectionConfig:

    def test_get_nonexistent_key_returns_none(self, store):
        assert store.get_config("does_not_exist") is None

    def test_set_and_get_config(self, store):
        store.set_config("netbox_url", "http://localhost:8000")
        assert store.get_config("netbox_url") == "http://localhost:8000"

    def test_update_existing_config(self, store):
        store.set_config("netbox_url", "http://old")
        store.set_config("netbox_url", "http://new")
        assert store.get_config("netbox_url") == "http://new"

    def test_get_all_config(self, store):
        store.set_config("a", "1")
        store.set_config("b", "2")
        cfg = store.get_all_config()
        assert cfg == {"a": "1", "b": "2"}

    def test_delete_config(self, store):
        store.set_config("key1", "val1")
        assert store.delete_config("key1") is True
        assert store.get_config("key1") is None

    def test_delete_nonexistent_config_returns_false(self, store):
        assert store.delete_config("nope") is False

    def test_empty_key_raises(self, store):
        with pytest.raises(SecretStoreError):
            store.set_config("", "value")

    def test_empty_value_raises(self, store):
        with pytest.raises(SecretStoreError):
            store.set_config("key", "")

    def test_values_are_encrypted_at_rest(self, store):
        """Raw column value in DB should not match the plaintext."""
        import sqlite3
        store.set_config("secret_key", "super_secret_value")
        conn = sqlite3.connect(store.db_path)
        row = conn.execute(
            "SELECT config_value FROM connection_config WHERE config_key = ?",
            ("secret_key",),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] != "super_secret_value"


# ── 4. Sync config (plain text) ─────────────────────────────────────────────

class TestSyncConfig:

    def test_get_nonexistent_sync_key_returns_none(self, store):
        assert store.get_sync_config("missing") is None

    def test_set_and_get_sync_config(self, store):
        store.set_sync_config("clustering", "true")
        assert store.get_sync_config("clustering") == "true"

    def test_update_sync_config(self, store):
        store.set_sync_config("clustering", "true")
        store.set_sync_config("clustering", "false")
        assert store.get_sync_config("clustering") == "false"

    def test_get_all_sync_config(self, store):
        store.set_sync_config("a", "1")
        store.set_sync_config("b", "2")
        assert store.get_all_sync_config() == {"a": "1", "b": "2"}

    def test_delete_sync_config(self, store):
        store.set_sync_config("key1", "val1")
        assert store.delete_sync_config("key1") is True
        assert store.get_sync_config("key1") is None

    def test_delete_nonexistent_sync_config_returns_false(self, store):
        assert store.delete_sync_config("nope") is False
