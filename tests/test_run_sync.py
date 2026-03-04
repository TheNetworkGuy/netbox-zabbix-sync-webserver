"""Tests for the run_sync background task.

Covers:
- Sync runs successfully with complete config
- Validation errors when connection config is incomplete
- Validation errors when Zabbix auth is incomplete
- Token auth preferred over user/pass in run_sync flow
- start() called with correct filters
"""
from unittest.mock import patch, MagicMock, call

import pytest

from app.sync_manager import SyncManager
from app.routes import run_sync


def _populate_connection_config(store, *, use_token=False):
    """Insert a full set of connection config into the store."""
    store.set_config("netbox_url", "http://nb:8000")
    store.set_config("netbox_token", "nbt_abc")
    store.set_config("zabbix_url", "http://zbx")
    if use_token:
        store.set_config("zabbix_token", "zbx_tok_123")
    else:
        store.set_config("zabbix_user", "Admin")
        store.set_config("zabbix_password", "zabbix")


class TestRunSync:

    def test_successful_sync_with_user_pass(self, store_with_secret):
        """Full sync with user/pass should call connect + start."""
        _populate_connection_config(store_with_secret, use_token=False)
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            instance = MockSync.return_value
            run_sync("evt-1", {"name": "SW01"}, None, store_with_secret, manager)

            instance.connect.assert_called_once()
            instance.start.assert_called_once_with(
                device_filter={"name": "SW01"},
                vm_filter=None,
            )

    def test_successful_sync_with_token(self, store_with_secret):
        """Full sync with token should call connect with zbx_token."""
        _populate_connection_config(store_with_secret, use_token=True)
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            instance = MockSync.return_value
            run_sync("evt-2", None, {"name": "VM01"}, store_with_secret, manager)

            _, kwargs = instance.connect.call_args
            assert kwargs["zbx_token"] == "zbx_tok_123"
            assert kwargs["zbx_user"] is None
            assert kwargs["zbx_pass"] is None
            instance.start.assert_called_once_with(
                device_filter=None,
                vm_filter={"name": "VM01"},
            )

    def test_token_preferred_over_user_pass(self, store_with_secret):
        """When both token and user/pass exist, token should be used."""
        _populate_connection_config(store_with_secret, use_token=False)
        store_with_secret.set_config("zabbix_token", "zbx_tok_preferred")
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            instance = MockSync.return_value
            run_sync("evt-3", None, None, store_with_secret, manager)

            _, kwargs = instance.connect.call_args
            assert kwargs["zbx_token"] == "zbx_tok_preferred"
            assert kwargs["zbx_user"] is None

    def test_missing_netbox_url_logs_error(self, store_with_secret, caplog):
        """Missing netbox_url should log an error, not crash."""
        # Only set partial config
        store_with_secret.set_config("netbox_token", "tok")
        store_with_secret.set_config("zabbix_url", "http://zbx")
        store_with_secret.set_config("zabbix_user", "Admin")
        store_with_secret.set_config("zabbix_password", "pass")
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            run_sync("evt-fail-1", None, None, store_with_secret, manager)
            MockSync.return_value.start.assert_not_called()
        assert "Missing required connection" in caplog.text

    def test_missing_zabbix_auth_logs_error(self, store_with_secret, caplog):
        """Missing Zabbix auth should log an error, not crash."""
        store_with_secret.set_config("netbox_url", "http://nb")
        store_with_secret.set_config("netbox_token", "tok")
        store_with_secret.set_config("zabbix_url", "http://zbx")
        # No zabbix_user, zabbix_password, or zabbix_token
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            run_sync("evt-fail-2", None, None, store_with_secret, manager)
            MockSync.return_value.start.assert_not_called()
        assert "Missing required Zabbix authentication" in caplog.text

    def test_start_not_called_on_connect_failure(self, store_with_secret, caplog):
        """If connect() returns False, start() must not be called."""
        _populate_connection_config(store_with_secret, use_token=False)
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            instance = MockSync.return_value
            instance.connect.return_value = False
            run_sync("evt-fail-3", None, None, store_with_secret, manager)

            instance.start.assert_not_called()
        assert "Sync operation failed" in caplog.text

    def test_second_sync_reuses_connection(self, store_with_secret):
        """Two consecutive syncs with same config should connect() only once."""
        _populate_connection_config(store_with_secret, use_token=False)
        manager = SyncManager(store_with_secret)

        with patch("app.sync_manager.Sync") as MockSync:
            instance = MockSync.return_value
            run_sync("evt-a", {"name": "SW01"}, None, store_with_secret, manager)
            run_sync("evt-b", {"name": "SW02"}, None, store_with_secret, manager)

            assert instance.connect.call_count == 1
            assert instance.start.call_count == 2
