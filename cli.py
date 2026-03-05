"""Command-line interface for the webserver."""

import argparse
import logging
import sys

from app.token_store import SecretStore, SecretStoreError

logger = logging.getLogger(__name__)


def handle_cli() -> int:
    """Handle CLI commands. Returns exit code."""
    parser = argparse.ArgumentParser(description="NB-sync webserver utilities")
    parser.add_argument(
        "--generate-secret",
        action="store_true",
        help="Generate and store a new webhook secret",
    )
    args = parser.parse_args()

    if args.generate_secret:
        try:
            store = SecretStore()
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
