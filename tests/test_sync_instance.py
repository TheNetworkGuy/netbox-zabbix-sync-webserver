"""Tests for Sync instance caching, connect logic, and auth selection.

Covers:
- Sync() not called when no sync config exists
- Sync() recreated when sync config changes
- connect() NOT called when connection details are incomplete
- connect() called with user/pass when no token is set
- connect() called with token (preferred) when token is set
- connect() re-called when connection config changes
- connect() NOT re-called on duplicate /sync with same config
"""

from unittest.mock import MagicMock, call, patch

import pytest

from app.sync_manager import SyncManager

# ── Helper ────────────────────────────────────────────────────────────────────


def _patch_sync_class():
    """Patch the Sync class used inside sync_manager so no real connections happen."""
    return patch("app.sync_manager.Sync")


# ── 3. connect() not called when connection details are missing ──────────────


class TestConnectNotCalledWithoutConfig:
    def test_missing_netbox_url(self, store_with_secret):
        """connect() must NOT be called when netbox_url is missing."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url=None,
                nb_token="tok",
                zbx_url="http://zbx",
                zbx_user="admin",
                zbx_pass="pass",
                zbx_token=None,
            )
            instance.connect.assert_not_called()

    def test_missing_zabbix_auth(self, store_with_secret):
        """connect() must NOT be called when neither token nor user+pass exist."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="tok",
                zbx_url="http://zbx",
                zbx_user=None,
                zbx_pass=None,
                zbx_token=None,
            )
            instance.connect.assert_not_called()

    def test_missing_zabbix_password_only(self, store_with_secret):
        """connect() must NOT be called when user is set but password is missing."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="tok",
                zbx_url="http://zbx",
                zbx_user="admin",
                zbx_pass=None,
                zbx_token=None,
            )
            instance.connect.assert_not_called()


# ── 4a. connect() auth selection ──────────────────────────────────────────────


class TestConnectAuthSelection:
    def test_connect_with_username_password(self, store_with_secret):
        """When only user/pass are set, connect() gets user+pass, token=None."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="nbt",
                zbx_url="http://zbx",
                zbx_user="Admin",
                zbx_pass="zabbix",
                zbx_token=None,
            )
            instance.connect.assert_called_once_with(
                "http://nb",
                "nbt",
                "http://zbx",
                zbx_user="Admin",
                zbx_pass="zabbix",
                zbx_token=None,
            )

    def test_connect_with_token(self, store_with_secret):
        """When token is set, connect() gets token only, user/pass=None."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="nbt",
                zbx_url="http://zbx",
                zbx_user=None,
                zbx_pass=None,
                zbx_token="zbx_api_token_123",
            )
            instance.connect.assert_called_once_with(
                "http://nb",
                "nbt",
                "http://zbx",
                zbx_user=None,
                zbx_pass=None,
                zbx_token="zbx_api_token_123",
            )

    def test_token_preferred_over_username_password(self, store_with_secret):
        """When BOTH token and user/pass are set, token wins."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="nbt",
                zbx_url="http://zbx",
                zbx_user="Admin",
                zbx_pass="zabbix",
                zbx_token="zbx_api_token_123",
            )
            instance.connect.assert_called_once_with(
                "http://nb",
                "nbt",
                "http://zbx",
                zbx_user=None,
                zbx_pass=None,
                zbx_token="zbx_api_token_123",
            )


# ── 4b. Reconnect / cache behaviour ──────────────────────────────────────────


class TestSyncInstanceCaching:
    def test_same_config_does_not_reconnect(self, store_with_secret):
        """Calling with identical config twice should only connect() once."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(**kwargs)
            manager.get_or_create_sync_instance(**kwargs)
            assert instance.connect.call_count == 1

    def test_changed_connection_config_triggers_reconnect(self, store_with_secret):
        """Changing connection parameters should re-call connect()."""
        manager = SyncManager(store_with_secret)

        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value

            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="nbt",
                zbx_url="http://zbx",
                zbx_user="Admin",
                zbx_pass="pass1",
                zbx_token=None,
            )
            manager.get_or_create_sync_instance(
                nb_url="http://nb",
                nb_token="nbt",
                zbx_url="http://zbx",
                zbx_user="Admin",
                zbx_pass="pass2",
                zbx_token=None,
            )
            assert instance.connect.call_count == 2

    def test_invalidate_connection_forces_reconnect(self, store_with_secret):
        """invalidate_connection() should cause the next call to reconnect."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(**kwargs)
            assert instance.connect.call_count == 1

            manager.invalidate_connection()
            manager.get_or_create_sync_instance(**kwargs)
            assert instance.connect.call_count == 2

    def test_changed_sync_config_recreates_instance(self, store_with_secret):
        """Changing sync config should create a new Sync() instance."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            manager.get_or_create_sync_instance(**kwargs)
            assert MockSync.call_count == 1

            # Simulate sync config change in the DB
            store_with_secret.set_sync_config("clustering", "true")
            manager.get_or_create_sync_instance(**kwargs)
            assert MockSync.call_count == 2

    def test_invalidate_instance_recreates_everything(self, store_with_secret):
        """invalidate_instance() should recreate Sync and re-connect."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(**kwargs)
            assert MockSync.call_count == 1
            assert instance.connect.call_count == 1

            manager.invalidate_instance()
            manager.get_or_create_sync_instance(**kwargs)
            assert MockSync.call_count == 2
            assert instance.connect.call_count == 2


# ── 6. cleanup() properly logs out and clears cache ──────────────────────────


class TestCleanup:
    def test_cleanup_calls_logout_when_instance_exists(self, store_with_secret):
        """cleanup() should call logout() on the Sync instance."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            manager.get_or_create_sync_instance(**kwargs)

            manager.cleanup()

            instance.logout.assert_called_once()

    def test_cleanup_clears_all_caches(self, store_with_secret):
        """cleanup() should clear instance, config_cache, and connection_cache."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            manager.get_or_create_sync_instance(**kwargs)

            # Verify caches are populated
            assert manager._instance is not None
            assert manager._config_cache is not None
            assert manager._connection_cache is not None

            manager.cleanup()

            # Verify all caches are cleared
            assert manager._instance is None
            assert manager._config_cache is None
            assert manager._connection_cache is None

    def test_cleanup_handles_logout_exception(self, store_with_secret):
        """cleanup() should handle exceptions during logout gracefully."""
        manager = SyncManager(store_with_secret)

        kwargs = dict(
            nb_url="http://nb",
            nb_token="nbt",
            zbx_url="http://zbx",
            zbx_user="Admin",
            zbx_pass="pass",
            zbx_token=None,
        )
        with _patch_sync_class() as MockSync:
            instance = MockSync.return_value
            instance.logout.side_effect = RuntimeError("Logout failed")

            manager.get_or_create_sync_instance(**kwargs)

            # Should not raise, even though logout() fails
            manager.cleanup()

            # Caches should still be cleared despite the exception
            assert manager._instance is None
            assert manager._config_cache is None
            assert manager._connection_cache is None

    def test_cleanup_does_nothing_when_no_instance(self, store_with_secret):
        """cleanup() should handle being called when no instance exists."""
        manager = SyncManager(store_with_secret)

        # Should not raise when called with no instance
        manager.cleanup()

        assert manager._instance is None
