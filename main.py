"""NetBox-Zabbix Sync Webserver entry point."""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import config
from app.routes import router, set_dependencies
from app.sync_manager import SyncManager
from app.token_store import SecretStoreError, store
from cli import handle_cli

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Set NetBox-Zabbix-sync logger to DEBUG if DEBUG_MODE is enabled
if config.DEBUG_MODE:
    logging.getLogger("NetBox-Zabbix-sync").setLevel(logging.DEBUG)


def warn_if_missing_secret() -> None:
    """Warn when no webhook secret exists in the store."""
    try:
        secret = store.get_cached_secret()
        if not secret:
            logger.warning("No webhook secret found. Generate one with --generate-secret")
    except SecretStoreError as exc:
        logger.error("Webhook secret DB error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    # Startup
    try:
        store.initialize()
    except SecretStoreError as exc:
        logger.error("Failed to initialize secret DB: %s", exc)
    else:
        warn_if_missing_secret()
    yield
    # Shutdown
    logger.info("Shutting down webserver...")
    sync_manager.cleanup()


app = FastAPI(lifespan=lifespan)

# Initialize dependencies
sync_manager = SyncManager(store)
set_dependencies(store, sync_manager)

# Include routes
app.include_router(router)


if __name__ == "__main__":
    sys.exit(handle_cli())
