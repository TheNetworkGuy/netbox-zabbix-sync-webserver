import argparse
import logging
import sys
from fastapi import FastAPI, Depends, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field
from netbox_zabbix_sync import Sync
from middleware import webhook_security_dependency
from token_store import store, SecretStoreError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI()

# Module-level cache for Sync instance
_sync_instance: Sync | None = None
_sync_config_cache: dict | None = None


def _convert_config_types(config_raw: dict) -> dict:
    """Convert string configuration values to appropriate Python types."""
    converted = {}
    for key, value in config_raw.items():
        # Convert boolean strings to actual booleans
        if value.lower() in ("true", "false"):
            converted[key] = value.lower() == "true"
        # Try to convert to int
        elif value.isdigit():
            converted[key] = int(value)
        else:
            converted[key] = value
    return converted


def get_or_create_sync_instance() -> Sync:
    """
    Get or create a Sync instance with current configuration.
    
    Caches the instance and recreates it only if the configuration has changed.
    """
    global _sync_instance, _sync_config_cache
    
    # Fetch current sync configuration
    sync_config_raw = store.get_all_sync_config()
    sync_config = _convert_config_types(sync_config_raw)
    
    # Check if we need to create a new instance
    if _sync_instance is None or _sync_config_cache != sync_config:
        logger.info("Creating new Sync instance with config: %s", sync_config)
        _sync_instance = Sync(sync_config)
        _sync_config_cache = sync_config.copy()
    
    return _sync_instance


def invalidate_sync_instance() -> None:
    """Invalidate the cached Sync instance, forcing recreation on next use."""
    global _sync_instance, _sync_config_cache
    _sync_instance = None
    _sync_config_cache = None
    logger.info("Sync instance cache invalidated")


def warn_if_missing_secret() -> None:
    """Warn when no webhook secret exists in the store."""
    try:
        secret = store.get_cached_secret()
        if not secret:
            logger.warning(
                "No webhook secret found. Generate one with --generate-secret"
            )
    except SecretStoreError as exc:
        logger.error("Webhook secret DB error: %s", exc)


@app.on_event("startup")
async def on_startup() -> None:
    try:
        store.initialize()
    except SecretStoreError as exc:
        logger.error("Failed to initialize secret DB: %s", exc)
        return
    warn_if_missing_secret()


def run_sync(event_id: str, device_filter: dict | None, vm_filter: dict | None):
    """Background task to run the sync operation."""
    logger.info("Starting sync operation for event %s", event_id)
    
    try:
        # Fetch connection configuration from database
        nb_url = store.get_config("netbox_url")
        nb_token = store.get_config("netbox_token")
        zbx_url = store.get_config("zabbix_url")
        zbx_user = store.get_config("zabbix_user")
        zbx_pass = store.get_config("zabbix_password") or store.get_config("zabbix_token")
        
        # Validate that all required config is available
        if not all([nb_url, nb_token, zbx_url, zbx_user, zbx_pass]):
            raise ValueError(
                "Missing required connection configuration. "
                "Please set all values via /connect_config endpoint"
            )
        
        # Get or create Sync instance with current configuration
        nbsync = get_or_create_sync_instance()
        
        # Connect and run sync with filters
        nbsync.connect(nb_url, nb_token, zbx_url, zbx_user, zbx_pass)
        nbsync.start(
            device_filter=device_filter,
            vm_filter=vm_filter
        )
        
        logger.info("Sync operation completed successfully for event %s", event_id)
    except (SecretStoreError, ValueError, RuntimeError) as exc:
        logger.error("Sync operation failed for event %s: %s", event_id, exc)


class SyncPayload(BaseModel):
    """Schema for incoming sync webhook data"""
    device_filter: dict | None = None
    vm_filter: dict | None = None
    timestamp: str | None = None


class ConnectionConfigPayload(BaseModel):
    """Schema for connection configuration updates"""
    netbox_url: str | None = Field(None, description="NetBox API URL")
    netbox_token: str | None = Field(None, description="NetBox API token")
    zabbix_url: str | None = Field(None, description="Zabbix API URL")
    zabbix_user: str | None = Field(None, description="Zabbix username")
    zabbix_password: str | None = Field(None, description="Zabbix password")
    zabbix_token: str | None = Field(None, description="Zabbix API token (alternative to password)")


class ConnectionConfigResponse(BaseModel):
    """Schema for connection configuration response"""
    status: str
    message: str
    updated_keys: list[str] | None = None


class SyncConfigPayload(BaseModel):
    """Schema for sync configuration updates"""
    config: dict[str, str] = Field(..., description="Sync configuration key-value pairs")


class SyncConfigResponse(BaseModel):
    """Schema for sync configuration response"""
    status: str
    message: str
    updated_keys: list[str] | None = None


@app.get("/")
async def root():
    return {"message": "Hello from NB-sync-webserver!"}


@app.post("/connect_config")
async def update_connection_config(
    config: ConnectionConfigPayload,
    security_info: dict = Depends(webhook_security_dependency)
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
                status="info",
                message="No configuration values provided to update"
            )
        
        logger.info("Successfully updated configuration keys: %s", updated_keys)
        
        return ConnectionConfigResponse(
            status="success",
            message=f"Successfully updated {len(updated_keys)} configuration value(s)",
            updated_keys=updated_keys
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
            detail="Unexpected error updating configuration"
        ) from exc


@app.get("/connect_config")
async def get_connection_config(
    security_info: dict = Depends(webhook_security_dependency)
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
            "note": "Sensitive values (tokens, passwords) are not returned for security"
        }
    except SecretStoreError as exc:
        logger.error("Failed to retrieve configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve configuration"
        ) from exc


@app.post("/sync_config")
async def update_sync_config(
    payload: SyncConfigPayload,
    security_info: dict = Depends(webhook_security_dependency)
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
            status="info",
            message="No configuration values provided to update"
        )
    
    updated_keys = []
    
    try:
        for key, value in payload.config.items():
            store.set_sync_config(key, str(value))
            updated_keys.append(key)
        
        # Invalidate cached Sync instance since config changed
        invalidate_sync_instance()
        
        logger.info("Successfully updated sync config keys: %s", updated_keys)
        
        return SyncConfigResponse(
            status="success",
            message=f"Successfully updated {len(updated_keys)} sync configuration value(s)",
            updated_keys=updated_keys
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
            detail="Unexpected error updating sync configuration"
        ) from exc


@app.get("/sync_config")
async def get_sync_config(
    security_info: dict = Depends(webhook_security_dependency)
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
        return {
            "status": "success",
            "config": config
        }
    except SecretStoreError as exc:
        logger.error("Failed to retrieve sync configuration: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve sync configuration"
        ) from exc


@app.delete("/sync_config/{key}")
async def delete_sync_config_key(
    key: str,
    security_info: dict = Depends(webhook_security_dependency)
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
            invalidate_sync_instance()
            return {
                "status": "success",
                "message": f"Successfully deleted sync config key: {key}"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sync config key '{key}' not found"
            )
    except SecretStoreError as exc:
        logger.error("Failed to delete sync config key '%s': %s", key, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete sync configuration"
        ) from exc



@app.post("/sync")
async def sync_webhook(
    payload: SyncPayload,
    background_tasks: BackgroundTasks,
    security_info: dict = Depends(webhook_security_dependency)
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
        payload.vm_filter
    )

    return {
        "status": "accepted",
        "message": "Sync request accepted and will be processed in the background",
        "event_id": security_info["event_id"],
        "device_filter": payload.device_filter,
        "vm_filter": payload.vm_filter
    }


def handle_cli() -> int:
    parser = argparse.ArgumentParser(description="NB-sync webserver utilities")
    parser.add_argument(
        "--generate-secret",
        action="store_true",
        help="Generate and store a new webhook secret"
    )
    args = parser.parse_args()

    if args.generate_secret:
        try:
            store.initialize()
            secret = store.generate_and_store_secret()
            print(secret)
            logger.info("New webhook secret generated and stored")
            return 0
        except SecretStoreError as exc:
            logger.error("Failed to generate secret: %s", exc)
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(handle_cli())
