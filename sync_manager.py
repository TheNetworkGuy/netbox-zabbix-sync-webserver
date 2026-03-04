"""Sync instance management with caching."""
import logging
from netbox_zabbix_sync import Sync
from token_store import SecretStore

logger = logging.getLogger(__name__)


def convert_config_types(config_raw: dict) -> dict:
    """Convert string configuration values to appropriate Python types."""
    converted = {}
    for key, value in config_raw.items():
        # Skip non-string values
        if not isinstance(value, str):
            converted[key] = value
            continue
        # Convert boolean strings to actual booleans
        if value.lower() in ("true", "false"):
            converted[key] = value.lower() == "true"
        # Try to convert to int
        elif value.isdigit():
            converted[key] = int(value)
        else:
            converted[key] = value
    return converted


class SyncManager:
    """Manages Sync instance lifecycle with configuration caching."""

    def __init__(self, store: SecretStore) -> None:
        self._store = store
        self._instance: Sync | None = None
        self._config_cache: dict | None = None
        self._connection_cache: dict | None = None

    def get_or_create_sync_instance(
        self,
        nb_url: str | None,
        nb_token: str | None,
        zbx_url: str | None,
        zbx_user: str | None,
        zbx_pass: str | None,
        zbx_token: str | None,
    ) -> Sync:
        """
        Get or create a Sync instance with current configuration.

        Caches the instance and recreates it only if the configuration has changed.
        Connects once connection configuration is available, and reconnects only if
        connection values change.
        """
        # Fetch current sync configuration
        sync_config_raw = self._store.get_all_sync_config()
        sync_config = convert_config_types(sync_config_raw)

        # Check if we need to create a new instance
        if self._instance is None or self._config_cache != sync_config:
            logger.info("Creating new Sync instance with config: %s", sync_config)
            self._instance = Sync(sync_config)
            self._config_cache = sync_config.copy()
            self._connection_cache = None

        connection_config = {
            "netbox_url": nb_url,
            "netbox_token": nb_token,
            "zabbix_url": zbx_url,
            "zabbix_user": zbx_user,
            "zabbix_password": zbx_pass,
            "zabbix_token": zbx_token,
        }

        if not nb_url or not nb_token or not zbx_url:
            return self._instance
        if not zbx_token and (not zbx_user or not zbx_pass):
            return self._instance

        if self._connection_cache != connection_config:
            use_token_auth = bool(zbx_token)
            zbx_auth_user = None if use_token_auth else zbx_user
            zbx_auth_pass = None if use_token_auth else zbx_pass
            zbx_auth_token = zbx_token if use_token_auth else None

            logger.info(
                "(Re)connecting Sync instance to NetBox/Zabbix using %s auth",
                "token" if use_token_auth else "username/password",
            )

            self._instance.connect(
                nb_url,
                nb_token,
                zbx_url,
                zbx_user=zbx_auth_user,
                zbx_pass=zbx_auth_pass,
                zbx_token=zbx_auth_token,
            )
            self._connection_cache = connection_config.copy()

        return self._instance

    def invalidate_instance(self) -> None:
        """Invalidate the cached Sync instance, forcing recreation on next use."""
        self._instance = None
        self._config_cache = None
        self._connection_cache = None
        logger.info("Sync instance cache invalidated")

    def invalidate_connection(self) -> None:
        """Invalidate the cached Sync connection, forcing reconnect on next use."""
        self._connection_cache = None
