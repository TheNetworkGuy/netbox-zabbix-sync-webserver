"""
Standalone webserver test script to send properly signed webhook requests.

Usage:
	python test_webserver.py

Make sure the server is running:
	uvicorn main:app --reload --port 8001
"""
import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

import requests


PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
	sys.path.insert(0, str(PROJECT_DIR))

# Set the database path to the webserver directory before importing
os.environ.setdefault("WEBHOOK_DB_PATH", str(PROJECT_DIR / "app_data.db"))

from app.token_store import SecretStoreError, store


def load_secret() -> str:
	"""Load the webhook secret from env or the SQLite store."""
	env_secret = os.getenv("WEBHOOK_SECRET")
	if env_secret:
		return env_secret

	try:
		store.initialize()
		secret = store.get_cached_secret()
		if secret:
			return secret
	except SecretStoreError as exc:
		print(f"❌ Failed to load secret: {exc}")

	print("❌ No webhook secret found. Generate one with:")
	print(f"   cd {PROJECT_DIR} && python main.py --generate-secret")
	sys.exit(1)


def generate_webhook_signature(timestamp: str, body: bytes, secret: str) -> str:
	"""Generate HMAC-SHA256 signature with format hmac_sha256(\"{timestamp}.{raw_body}\")."""
	message = f"{timestamp}.{body.decode('utf-8')}"
	return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


def post_signed_json(
	url: str,
	data: dict,
	secret: str,
	event_id: Optional[str] = None,
) -> requests.Response:
	"""Send a signed JSON POST request using webhook security headers."""
	if event_id is None:
		event_id = str(uuid.uuid4())

	timestamp = str(int(time.time()))
	json_body = json.dumps(data, separators=(",", ":"))
	body_bytes = json_body.encode("utf-8")
	signature = generate_webhook_signature(timestamp, body_bytes, secret)

	headers = {
		"Content-Type": "application/json",
		"X-Signature": signature,
		"X-Timestamp": timestamp,
		"X-Event-ID": event_id,
	}

	print("=" * 60)
	print("Sending signed request to:", url)
	print("-" * 60)
	print(f"Event ID:  {event_id}")
	print(f"Timestamp: {timestamp}")
	print(f"Signature: {signature}")
	print(f"Payload:   {json_body}")
	print("-" * 60)

	response = requests.post(url, headers=headers, data=body_bytes, timeout=10)

	print(f"Status Code: {response.status_code}")
	try:
		print(f"Response:    {response.json()}")
	except ValueError:
		print(f"Response:    {response.text}")
	print("=" * 60)

	return response


def send_webhook(
	url: str = "http://localhost:8001/sync",
	data: Optional[dict] = None,
	secret: Optional[str] = None,
	event_id: Optional[str] = None,
) -> requests.Response:
	"""Send a properly signed webhook request."""
	if data is None:
		data = {}

	if secret is None:
		secret = load_secret()

	return post_signed_json(url=url, data=data, secret=secret, event_id=event_id)


def send_connect_config_update(
	url: str = "http://localhost:8001/connect_config",
	data: Optional[dict] = None,
	secret: Optional[str] = None,
	event_id: Optional[str] = None,
) -> requests.Response:
	"""Send a signed request to update connection config."""
	if data is None:
		data = {"netbox_url": "http://127.0.0.1:8000"}

	if secret is None:
		secret = load_secret()

	return post_signed_json(url=url, data=data, secret=secret, event_id=event_id)


def send_sync_config_update(
	url: str = "http://localhost:8001/sync_config",
	data: Optional[dict] = None,
	secret: Optional[str] = None,
	event_id: Optional[str] = None,
) -> requests.Response:
	"""Send a signed request to update sync configuration."""
	if data is None:
		data = {
			"config": {
				"clustering": "true",
				"template_cf": "zbx_template",
			}
		}

	if secret is None:
		secret = load_secret()

	return post_signed_json(url=url, data=data, secret=secret, event_id=event_id)


if __name__ == "__main__":



	# print("Test: Webhook with device filter only")
	# send_webhook(data={"device_filter": {"name": "SW01N0"}})

	print("Test: Webhook without filters")
	send_webhook()

	# print("\nTest: Update connect config (netbox_url)")
	# send_connect_config_update(data={"netbox_url": "http://127.0.0.1:8000"})

	# print("\nTest: Update connect config (multiple values)")
	# send_connect_config_update(
	#     data={
	#         "netbox_url": "http://127.0.0.1:8000",
	#         "netbox_token": "nbt_geXovN0NThHK.d8pHXcENlq7PQL3Vo6br8Pw0UdqZ038Y0NVrzTy0",
	#         "zabbix_url": "http://127.0.0.1",
	#         "zabbix_user": "Admin",
	#         "zabbix_password": "zabbix",
	#     }
	# )

	# print("\nTest: Update sync config (clustering and template_cf)")
	# send_sync_config_update(
	#     data={
	#         "config": {
	#             "clustering": "true",
	#             # "template_cf": "zabbix_template",
	#         }
	#     }
	# )
