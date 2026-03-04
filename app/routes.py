"""FastAPI route definitions."""
import logging
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, status

from app.middleware import webhook_security_dependency
from app.models import (
    SyncPayload,
    ConnectionConfigPayload,
    ConnectionConfigResponse,
    SyncConfigPayload,
    SyncConfigResponse,
)
from app.token_store import SecretStore, SecretStoreError
from app.sync_manager import SyncManager

logger = logging.getLogger(__name__)

router = APIRouter()

# These will be set by main.py during app initialization
_store: SecretStore | None = None
_sync_manager: SyncManager | None = None


def set_dependencies(store: SecretStore, sync_manager: SyncManager) -> None:
    """Set module-level dependencies (called from main.py)."""
    global _store, _sync_manager
    _store = store
    _sync_manager = sync_manager


def get_store() -> SecretStore:
    """Dependency to get the SecretStore instance."""
    if _store is None:
        raise RuntimeError("Store not initialized")
    return _store


def get_sync_manager() -> SyncManager:
    """Dependency to get the SyncManager instance."""
    if _sync_manager is None:
        raise RuntimeError("SyncManager not initialized")
    return _sync_manager


def run_sync(
    event_id: str,
    device_filter: dict | None,
    vm_filter: dict | None,
    store: SecretStore,
    sync_manager: SyncManager,
) -> None:
    """Background task to run the sync operation."""
    logger.info("Starting sync operation for event %s", event_id)

    try:
        # Fetch connection configuration from database
        nb_url = store.get_config("netbox_url")
        nb_token = store.get_config("netbox_token")
        zbx_url = store.get_config("zabbix_url")
        zbx_user = store.get_config("zabbix_user")
        zbx_pass = store.get_config("zabbix_password")
        zbx_token = store.get_config("zabbix_token")

        # Validate that all required config is available
        if not nb_url or not nb_token or not zbx_url:
            raise ValueError(
                "Missing required connection configuration. "
                "Please set all values via /connect_config endpoint"
            )
        if not zbx_token and (not zbx_user or not zbx_pass):
            raise ValueError(
                "Missing required Zabbix authentication configuration. "
                "Provide zabbix_token or zabbix_user + zabbix_password"
            )

        # Get or create Sync instance with current configuration and connect once
        nbsync = sync_manager.get_or_create_sync_instance(
            nb_url,
            nb_token,
            zbx_url,
            zbx_user,
            zbx_pass,
            zbx_token,
        )

        # Run sync with filters
        nbsync.start(device_filter=device_filter, vm_filter=vm_filter)

        logger.info("Sync operation completed successfully for event %s", event_id)
    except (SecretStoreError, ValueError, RuntimeError) as exc:
        logger.error("Sync operation failed for event %s: %s", event_id, exc)


@router.get("/")
async def root():
    return {"message": "Hello from NB-sync-webserver!"}


@router.post("/connect_config")
async def update_connection_config(
    config: ConnectionConfigPayload,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
) -> ConnectionConfigResponse:
    """
    Update connection configuration for NetBox and Zabbix.

    Requires webhook authentication. Stores credentials securely in the database.
    You can update one or multiple configuration values at a time.

    Supported keys:
    - netbox_url: NetBox API URL (e.g., http://localhost:8000)
    - netbox_token: NetBox API token
    - zabbix_url: Zabbix API URL (e.g., http://localhost)
    - zabbix_user: Zabbix username
    - zabbix_password: Zabbix password
    - zabbix_token: Zabbix API token (alternative to password)
    """
    logger.info(
        "Connection config update from %s (event %s)",
        security_info["client_ip"],
        security_info["event_id"],
    )

    updated_keys = []

    try:
        # Update only the provided fields
        if config.netbox_url is not None:
            store.set_config("netbox_url", config.netbox_url)
            updated_keys.append("netbox_url")

        if config.netbox_token is not None:
            store.set_config("netbox_token", config.netbox_token)
            updated_keys.append("netbox_token")

        if config.zabbix_url is not None:
            store.set_config("zabbix_url", config.zabbix_url)
            updated_keys.append("zabbix_url")

        if config.zabbix_user is not None:
            store.set_config("zabbix_user", config.zabbix_user)
            updated_keys.append("zabbix_user")

        if config.zabbix_password is not None:
            store.set_config("zabbix_password", config.zabbix_password)
            updated_keys.append("zabbix_password")

        if config.zabbix_token is not None:
            store.set_config("zabbix_token", config.zabbix_token)
            updated_keys.append("zabbix_token")

        if not updated_keys:
            return ConnectionConfigResponse(
                status="info", message="No configuration values provided to update"
            )

        logger.info("Successfully updated configuration keys: %s", updated_keys)

        sync_manager.invalidate_connection()
        logger.info(
            "Connection config changed in DB; Sync will reconnect on next /sync"
        )

        return ConnectionConfigResponse(
            status="success",
            message=f"Successfully updated {len(updated_keys)} configuration value(s)",
            updated_keys=updated_keys,
        )

    except SecretStoreError as exc:
        logger.error("Failed to update configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store configuration: {str(exc)}",
        ) from exc
    except Exception as exc:
        logger.error("Unexpected error updating configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error updating configuration",
        ) from exc


@router.patch("/connect_config")
async def patch_connection_config(
    config: ConnectionConfigPayload,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
) -> ConnectionConfigResponse:
    """
    Partially update connection configuration for NetBox and Zabbix.

    Alias for POST /connect_config with proper REST semantics (PATCH for partial updates).
    """
    return await update_connection_config(config, security_info, store, sync_manager)


@router.get("/connect_config")
async def get_connection_config(
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
) -> dict:
    """
    Retrieve current connection configuration (public values only).

    Requires webhook authentication. Returns URLs and usernames but NOT tokens/passwords.
    """
    logger.info(
        "Connection config retrieval from %s (event %s)",
        security_info["client_ip"],
        security_info["event_id"],
    )

    try:
        config = store.get_all_config()
        # Return only non-sensitive values
        public_config = {
            key: value
            for key, value in config.items()
            if key in ["netbox_url", "zabbix_url", "zabbix_user"]
        }
        return {
            "status": "success",
            "config": public_config,
            "note": "Sensitive values (tokens, passwords) are not returned for security",
        }
    except SecretStoreError as exc:
        logger.error("Failed to retrieve configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve configuration",
        ) from exc


@router.post("/sync_config")
async def update_sync_config(
    payload: SyncConfigPayload,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
) -> SyncConfigResponse:
    """
    Update sync configuration for the NetBox-Zabbix sync operation.

    Requires webhook authentication. Stores configuration values in plain text.
    You can update one or multiple configuration values at a time.

    Common configuration keys (invalid keys will be ignored by Sync class):
    - clustering: Enable clustering support (true/false)
    - template_cf: Custom field name for Zabbix template
    - host_group: Zabbix host group name
    - proxy: Zabbix proxy name

    Example payload:
    {
        "config": {
            "clustering": "true",
            "template_cf": "zbx_template"
        }
    }
    """
    logger.info(
        "Sync config update from %s (event %s)",
        security_info["client_ip"],
        security_info["event_id"],
    )

    if not payload.config:
        return SyncConfigResponse(
            status="info", message="No configuration values provided to update"
        )

    updated_keys = []

    try:
        for key, value in payload.config.items():
            store.set_sync_config(key, str(value))
            updated_keys.append(key)

        # Invalidate cached Sync instance since config changed
        sync_manager.invalidate_instance()

        logger.info("Successfully updated sync config keys: %s", updated_keys)

        return SyncConfigResponse(
            status="success",
            message=f"Successfully updated {len(updated_keys)} sync configuration value(s)",
            updated_keys=updated_keys,
        )

    except SecretStoreError as exc:
        logger.error("Failed to update sync configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store sync configuration: {str(exc)}",
        ) from exc
    except Exception as exc:
        logger.error("Unexpected error updating sync configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unexpected error updating sync configuration",
        ) from exc


@router.patch("/sync_config")
async def patch_sync_config(
    payload: SyncConfigPayload,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
) -> SyncConfigResponse:
    """
    Partially update sync configuration.

    Alias for POST /sync_config with proper REST semantics (PATCH for partial updates).
    """
    return await update_sync_config(payload, security_info, store, sync_manager)


@router.get("/sync_config")
async def get_sync_config(
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
) -> dict:
    """
    Retrieve current sync configuration.

    Requires webhook authentication. Returns all sync configuration key-value pairs.
    """
    logger.info(
        "Sync config retrieval from %s (event %s)",
        security_info["client_ip"],
        security_info["event_id"],
    )

    try:
        config = store.get_all_sync_config()
        return {"status": "success", "config": config}
    except SecretStoreError as exc:
        logger.error("Failed to retrieve sync configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sync configuration",
        ) from exc


@router.delete("/sync_config/{key}")
async def delete_sync_config_key(
    key: str,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
) -> dict:
    """
    Delete a specific sync configuration key.

    Requires webhook authentication.
    """
    logger.info(
        "Sync config deletion for key '%s' from %s (event %s)",
        key,
        security_info["client_ip"],
        security_info["event_id"],
    )

    try:
        deleted = store.delete_sync_config(key)
        if deleted:
            # Invalidate cached Sync instance since config changed
            sync_manager.invalidate_instance()
            return {
                "status": "success",
                "message": f"Successfully deleted sync config key: {key}",
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sync config key '{key}' not found",
            )
    except SecretStoreError as exc:
        logger.error("Failed to delete sync config key '%s': %s", key, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete sync configuration",
        ) from exc


@router.post("/sync")
async def sync_webhook(
    payload: SyncPayload,
    background_tasks: BackgroundTasks,
    security_info: dict = Depends(webhook_security_dependency),
    store: SecretStore = Depends(get_store),
    sync_manager: SyncManager = Depends(get_sync_manager),
):
    """
    Webhook endpoint for incoming sync data.

    Security validation is performed by the webhook_security_dependency
    before this endpoint logic runs. The sync operation runs in the background
    after the response is sent.
    """
    logger.info(
        "Webhook received for event %s from %s",
        security_info["event_id"],
        security_info["client_ip"],
    )

    # Schedule the sync to run in the background
    background_tasks.add_task(
        run_sync,
        security_info["event_id"],
        payload.device_filter,
        payload.vm_filter,
        store,
        sync_manager,
    )

    return {
        "status": "accepted",
        "message": "Sync request accepted and will be processed in the background",
        "event_id": security_info["event_id"],
        "device_filter": payload.device_filter,
        "vm_filter": payload.vm_filter,
    }
