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


@pytest.fixture(autouse=True)
def _reset_main_caches():
    import main as m
    m._sync_instance = None
    m._sync_config_cache = None
    m._sync_connection_cache = None
    yield
    m._sync_instance = None
    m._sync_config_cache = None
    m._sync_connection_cache = None


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

    def test_successful_sync_with_user_pass(self, store_with_secret, monkeypatch):
        """Full sync with user/pass should call connect + start."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        _populate_connection_config(store_with_secret, use_token=False)

        with patch("main.Sync") as MockSync:
            instance = MockSync.return_value
            m.run_sync("evt-1", {"name": "SW01"}, None)

            instance.connect.assert_called_once()
            instance.start.assert_called_once_with(
                device_filter={"name": "SW01"},
                vm_filter=None,
            )

    def test_successful_sync_with_token(self, store_with_secret, monkeypatch):
        """Full sync with token should call connect with zbx_token."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        _populate_connection_config(store_with_secret, use_token=True)

        with patch("main.Sync") as MockSync:
            instance = MockSync.return_value
            m.run_sync("evt-2", None, {"name": "VM01"})

            _, kwargs = instance.connect.call_args
            assert kwargs["zbx_token"] == "zbx_tok_123"
            assert kwargs["zbx_user"] is None
            assert kwargs["zbx_pass"] is None
            instance.start.assert_called_once_with(
                device_filter=None,
                vm_filter={"name": "VM01"},
            )

    def test_token_preferred_over_user_pass(self, store_with_secret, monkeypatch):
        """When both token and user/pass exist, token should be used."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        _populate_connection_config(store_with_secret, use_token=False)
        store_with_secret.set_config("zabbix_token", "zbx_tok_preferred")

        with patch("main.Sync") as MockSync:
            instance = MockSync.return_value
            m.run_sync("evt-3", None, None)

            _, kwargs = instance.connect.call_args
            assert kwargs["zbx_token"] == "zbx_tok_preferred"
            assert kwargs["zbx_user"] is None

    def test_missing_netbox_url_logs_error(self, store_with_secret, monkeypatch, caplog):
        """Missing netbox_url should log an error, not crash."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        # Only set partial config
        store_with_secret.set_config("netbox_token", "tok")
        store_with_secret.set_config("zabbix_url", "http://zbx")
        store_with_secret.set_config("zabbix_user", "Admin")
        store_with_secret.set_config("zabbix_password", "pass")

        with patch("main.Sync") as MockSync:
            m.run_sync("evt-fail-1", None, None)
            MockSync.return_value.start.assert_not_called()
        assert "Missing required connection" in caplog.text

    def test_missing_zabbix_auth_logs_error(self, store_with_secret, monkeypatch, caplog):
        """Missing Zabbix auth should log an error, not crash."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        store_with_secret.set_config("netbox_url", "http://nb")
        store_with_secret.set_config("netbox_token", "tok")
        store_with_secret.set_config("zabbix_url", "http://zbx")
        # No zabbix_user, zabbix_password, or zabbix_token

        with patch("main.Sync") as MockSync:
            m.run_sync("evt-fail-2", None, None)
            MockSync.return_value.start.assert_not_called()
        assert "Missing required Zabbix authentication" in caplog.text

    def test_start_not_called_on_connect_failure(
        self, store_with_secret, monkeypatch, caplog
    ):
        """If connect() raises, start() must not be called."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        _populate_connection_config(store_with_secret, use_token=False)

        with patch("main.Sync") as MockSync:
            instance = MockSync.return_value
            instance.connect.side_effect = RuntimeError("connection refused")
            m.run_sync("evt-fail-3", None, None)

            instance.start.assert_not_called()
        assert "Sync operation failed" in caplog.text

    def test_second_sync_reuses_connection(self, store_with_secret, monkeypatch):
        """Two consecutive syncs with same config should connect() only once."""
        import main as m
        monkeypatch.setattr(m, "store", store_with_secret)
        _populate_connection_config(store_with_secret, use_token=False)

        with patch("main.Sync") as MockSync:
            instance = MockSync.return_value
            m.run_sync("evt-a", {"name": "SW01"}, None)
            m.run_sync("evt-b", {"name": "SW02"}, None)

            assert instance.connect.call_count == 1
            assert instance.start.call_count == 2
