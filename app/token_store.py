"""SQLite-backed storage for webhook secrets and connection configuration."""

import base64
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "app_data.db"


class SecretStoreError(RuntimeError):
    """Raised when secret storage operations fail."""


class SecretStore:
    """Manages storing and loading webhook secrets and connection config in SQLite."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or os.getenv("WEBHOOK_DB_PATH", DEFAULT_DB_PATH)
        self._secret_cache: str | None = None
        self._cipher: Fernet | None = None
        self._config_cache: dict | None = None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _load_or_create_encryption_key(self) -> bytes:
        """Load encryption key from env/file, creating a local key file if needed."""
        env_key = os.getenv("CONNECT_CONFIG_ENCRYPTION_KEY")
        if env_key:
            return env_key.encode()

        key_path = Path(f"{self.db_path}.key")
        if key_path.exists():
            return key_path.read_bytes().strip()

        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        try:
            os.chmod(key_path, 0o600)
        except PermissionError:
            logger.warning("Unable to set permissions on %s", key_path)
        return key

    def _init_cipher(self) -> Fernet:
        """Initialize or return the Fernet cipher."""
        if self._cipher is None:
            key = self._load_or_create_encryption_key()
            try:
                # Validate key format so startup/storage fails fast with clear error.
                raw = base64.urlsafe_b64decode(key)
                if len(raw) != 32:
                    raise ValueError("Invalid key length")
            except ValueError as exc:
                raise SecretStoreError(
                    "Invalid CONNECT_CONFIG_ENCRYPTION_KEY format. "
                    "Expected urlsafe base64 32-byte key."
                ) from exc
            self._cipher = Fernet(key)
        return self._cipher

    def initialize(self) -> None:
        """Ensure the database and tables exist."""
        try:
            db_file = Path(self.db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS auth_secrets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        secret TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS connection_config (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        config_key TEXT NOT NULL UNIQUE,
                        config_value TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sync_config (
                        config_key TEXT PRIMARY KEY,
                        config_value TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            try:
                os.chmod(db_file, 0o600)
            except PermissionError:
                logger.warning("Unable to set permissions on %s", db_file)
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to initialize DB: {exc}") from exc

    def get_latest_secret(self) -> str | None:
        """Return the most recently stored secret, if any."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT secret FROM auth_secrets ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if row:
                    return row[0]
                return None
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to read secret from DB: {exc}") from exc

    def store_secret(self, secret: str) -> None:
        """Store a new secret."""
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO auth_secrets (secret, created_at) VALUES (?, ?)",
                    (secret, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
            self._secret_cache = secret
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to store secret: {exc}") from exc

    def generate_and_store_secret(self, length: int = 48) -> str:
        """Generate a new secret and store it in the DB."""
        secret = secrets.token_urlsafe(length)
        self.store_secret(secret)
        return secret

    def get_cached_secret(self) -> str | None:
        """Return cached secret, loading from DB on first access."""
        if self._secret_cache is None:
            self._secret_cache = self.get_latest_secret()
        return self._secret_cache

    def refresh_cache(self) -> str | None:
        """Force reload the secret from the DB."""
        self._secret_cache = self.get_latest_secret()
        return self._secret_cache

    def _encrypt(self, value: str) -> str:
        """Encrypt a value using Fernet."""
        cipher = self._init_cipher()
        encrypted = cipher.encrypt(value.encode())
        return encrypted.decode()

    def _decrypt(self, encrypted_value: str) -> str | None:
        """Decrypt a value using Fernet."""
        try:
            cipher = self._init_cipher()
            decrypted = cipher.decrypt(encrypted_value.encode())
            return decrypted.decode()
        except InvalidToken:
            logger.error("Failed to decrypt value - invalid token")
            return None
        except (ValueError, UnicodeDecodeError) as exc:
            logger.error("Decryption error: %s", exc)
            return None

    def set_config(self, key: str, value: str) -> None:
        """Store or update an encrypted configuration value."""
        if not key or not value:
            raise SecretStoreError("Config key and value cannot be empty")

        try:
            encrypted_value = self._encrypt(value)
            now_iso = datetime.now(timezone.utc).isoformat()

            with self._connect() as conn:
                # Try to update first
                cursor = conn.execute(
                    """
                    UPDATE connection_config 
                    SET config_value = ?, updated_at = ?
                    WHERE config_key = ?
                    """,
                    (encrypted_value, now_iso, key),
                )

                # If no rows were updated, insert a new one
                if cursor.rowcount == 0:
                    conn.execute(
                        """
                        INSERT INTO connection_config 
                        (config_key, config_value, created_at, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (key, encrypted_value, now_iso, now_iso),
                    )
                conn.commit()

            # Invalidate cache
            self._config_cache = None
        except sqlite3.IntegrityError as exc:
            raise SecretStoreError(f"Config key '{key}' error: {exc}") from exc
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to store config: {exc}") from exc

    def get_config(self, key: str) -> str | None:
        """Retrieve and decrypt a configuration value."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT config_value FROM connection_config WHERE config_key = ?", (key,)
                ).fetchone()

                if row:
                    encrypted_value = row[0]
                    return self._decrypt(encrypted_value)
                return None
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to read config from DB: {exc}") from exc

    def get_all_config(self) -> dict:
        """Retrieve all configuration values (decrypted)."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT config_key, config_value FROM connection_config"
                ).fetchall()

                result = {}
                for key, encrypted_value in rows:
                    decrypted = self._decrypt(encrypted_value)
                    if decrypted:
                        result[key] = decrypted
                return result
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to read all config from DB: {exc}") from exc

    def delete_config(self, key: str) -> bool:
        """Delete a configuration value. Returns True if deleted, False if not found."""
        try:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM connection_config WHERE config_key = ?", (key,))
                conn.commit()
                deleted = cursor.rowcount > 0

            if deleted:
                self._config_cache = None
            return deleted
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to delete config: {exc}") from exc

    def set_sync_config(self, key: str, value: str) -> None:
        """Store or update a plain-text sync configuration value."""
        if not key or value is None:
            raise SecretStoreError("Sync config key and value cannot be empty")

        try:
            now_iso = datetime.now(timezone.utc).isoformat()

            with self._connect() as conn:
                # Try to update first
                cursor = conn.execute(
                    """
                    UPDATE sync_config 
                    SET config_value = ?, updated_at = ?
                    WHERE config_key = ?
                    """,
                    (value, now_iso, key),
                )

                # If no rows were updated, insert a new one
                if cursor.rowcount == 0:
                    conn.execute(
                        """
                        INSERT INTO sync_config 
                        (config_key, config_value, created_at, updated_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (key, value, now_iso, now_iso),
                    )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise SecretStoreError(f"Sync config key '{key}' error: {exc}") from exc
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to store sync config: {exc}") from exc

    def get_sync_config(self, key: str) -> str | None:
        """Retrieve a plain-text sync configuration value."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT config_value FROM sync_config WHERE config_key = ?", (key,)
                ).fetchone()

                if row:
                    return row[0]
                return None
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to read sync config from DB: {exc}") from exc

    def get_all_sync_config(self) -> dict:
        """Retrieve all sync configuration values as a dictionary."""
        try:
            with self._connect() as conn:
                rows = conn.execute("SELECT config_key, config_value FROM sync_config").fetchall()

                return {key: value for key, value in rows}
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to read all sync config from DB: {exc}") from exc

    def delete_sync_config(self, key: str) -> bool:
        """Delete a sync configuration value. Returns True if deleted, False if not found."""
        try:
            with self._connect() as conn:
                cursor = conn.execute("DELETE FROM sync_config WHERE config_key = ?", (key,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as exc:
            raise SecretStoreError(f"Failed to delete sync config: {exc}") from exc


store = SecretStore()
