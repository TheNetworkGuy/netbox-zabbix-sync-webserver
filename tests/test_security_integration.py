"""Integration tests for webhook security middleware.

Tests all security controls through actual HTTP requests:
- HMAC signature verification
- Missing required headers
- Timestamp validation (expired/future)
- Event ID deduplication (replay attacks)
- Rate limiting
- Body size limits
- IP whitelisting (when configured)

These tests use the actual security middleware, unlike test_endpoints.py
which bypasses security for easier functional testing.
"""

import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.sync_manager import SyncManager
from app import security
import app.routes as routes
import main as main_mod


# ---------------------------------------------------------------------------
# Fixtures for security testing (no security bypass)
# ---------------------------------------------------------------------------


@pytest.fixture()
def secure_client(store_with_secret):
    """
    FastAPI TestClient WITHOUT security bypass.
    Tests will need to send properly signed requests.
    Patches get_client_ip since TestClient uses 'testclient' as IP.
    Patches security.store to use our test store instance.
    """
    manager = SyncManager(store_with_secret)
    routes.set_dependencies(store_with_secret, manager)

    # Patch get_client_ip since TestClient doesn't set a real IP
    # Patch security.store to use our test store (global store uses different DB)
    with (
        patch.object(security, "get_client_ip", return_value="127.0.0.1"),
        patch.object(security, "store", store_with_secret),
    ):
        with TestClient(main_mod.app) as tc:
            yield tc

    routes._store = None
    routes._sync_manager = None


def _sign_request(
    payload: dict,
    secret: str,
    timestamp: str | None = None,
    event_id: str | None = None,
):
    """Build headers and body for a signed webhook request."""
    if event_id is None:
        event_id = str(uuid.uuid4())
    if timestamp is None:
        timestamp = str(int(time.time()))

    body = json.dumps(payload, separators=(",", ":")).encode()
    message = f"{timestamp}.{body.decode()}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": event_id,
    }
    return headers, body


# ---------------------------------------------------------------------------
# Valid Request Tests
# ---------------------------------------------------------------------------


class TestValidRequest:
    """Tests that properly signed requests are accepted."""

    def test_valid_signed_request_accepted(self, secure_client, store_with_secret):
        """A properly signed request should return 200."""
        secret = store_with_secret.get_cached_secret()
        headers, body = _sign_request({}, secret)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    def test_valid_request_with_payload(self, secure_client, store_with_secret):
        """A signed request with filters should be accepted."""
        secret = store_with_secret.get_cached_secret()
        payload = {"device_filter": {"name": "SW01"}, "vm_filter": {"cluster": "prod"}}
        headers, body = _sign_request(payload, secret)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["device_filter"] == {"name": "SW01"}
        assert data["vm_filter"] == {"cluster": "prod"}


# ---------------------------------------------------------------------------
# Signature Verification Tests
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    """Tests for HMAC-SHA256 signature validation."""

    def test_invalid_signature_rejected(self, secure_client, store_with_secret):
        """Request with wrong signature should return 401."""
        timestamp = str(int(time.time()))
        body = json.dumps({}).encode()
        event_id = str(uuid.uuid4())

        headers = {
            "Content-Type": "application/json",
            "X-Signature": "invalid_signature_123",
            "X-Timestamp": timestamp,
            "X-Event-ID": event_id,
        }

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 401
        assert "Invalid signature" in resp.json()["detail"]

    def test_wrong_secret_rejected(self, secure_client, store_with_secret):
        """Request signed with wrong secret should return 401."""
        headers, body = _sign_request({}, "wrong-secret-key")

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 401
        assert "Invalid signature" in resp.json()["detail"]

    def test_tampered_body_rejected(self, secure_client, store_with_secret):
        """Request with modified body after signing should return 401."""
        secret = store_with_secret.get_cached_secret()

        # Sign original payload
        original_payload = {"test": "original"}
        headers, _ = _sign_request(original_payload, secret)

        # Send modified payload with original signature
        modified_body = json.dumps({"test": "modified"}).encode()

        resp = secure_client.post("/sync", headers=headers, content=modified_body)
        assert resp.status_code == 401
        assert "Invalid signature" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Missing Header Tests
# ---------------------------------------------------------------------------


class TestMissingHeaders:
    """Tests for missing required security headers."""

    def test_missing_signature_header(self, secure_client):
        """Request without X-Signature should return 400."""
        headers = {
            "Content-Type": "application/json",
            "X-Timestamp": str(int(time.time())),
            "X-Event-ID": str(uuid.uuid4()),
        }

        resp = secure_client.post("/sync", headers=headers, content=b"{}")
        assert resp.status_code == 400
        assert "X-Signature" in resp.json()["detail"]

    def test_missing_timestamp_header(self, secure_client):
        """Request without X-Timestamp should return 400."""
        headers = {
            "Content-Type": "application/json",
            "X-Signature": "some_signature",
            "X-Event-ID": str(uuid.uuid4()),
        }

        resp = secure_client.post("/sync", headers=headers, content=b"{}")
        assert resp.status_code == 400
        assert "X-Timestamp" in resp.json()["detail"]

    def test_missing_event_id_header(self, secure_client):
        """Request without X-Event-ID should return 400."""
        headers = {
            "Content-Type": "application/json",
            "X-Signature": "some_signature",
            "X-Timestamp": str(int(time.time())),
        }

        resp = secure_client.post("/sync", headers=headers, content=b"{}")
        assert resp.status_code == 400
        assert "X-Event-ID" in resp.json()["detail"]

    def test_all_headers_missing(self, secure_client):
        """Request with no security headers should return 400."""
        headers = {"Content-Type": "application/json"}

        resp = secure_client.post("/sync", headers=headers, content=b"{}")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Timestamp Validation Tests
# ---------------------------------------------------------------------------


class TestTimestampValidation:
    """Tests for timestamp window validation."""

    def test_expired_timestamp_rejected(self, secure_client, store_with_secret):
        """Request with timestamp older than 10 minutes should return 401."""
        secret = store_with_secret.get_cached_secret()
        old_timestamp = str(int(time.time()) - 15 * 60)  # 15 minutes ago
        headers, body = _sign_request({}, secret, timestamp=old_timestamp)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 401
        assert "timestamp" in resp.json()["detail"].lower()

    def test_future_timestamp_rejected(self, secure_client, store_with_secret):
        """Request with timestamp more than 10 minutes in future should return 401."""
        secret = store_with_secret.get_cached_secret()
        future_timestamp = str(int(time.time()) + 15 * 60)  # 15 minutes ahead
        headers, body = _sign_request({}, secret, timestamp=future_timestamp)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 401
        assert "timestamp" in resp.json()["detail"].lower()

    def test_invalid_timestamp_format_rejected(self, secure_client, store_with_secret):
        """Request with non-numeric timestamp should return 401."""
        secret = store_with_secret.get_cached_secret()
        headers, body = _sign_request({}, secret, timestamp="not-a-timestamp")

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 401

    def test_timestamp_near_boundary_accepted(self, secure_client, store_with_secret):
        """Request with timestamp 5 minutes old should be accepted."""
        secret = store_with_secret.get_cached_secret()
        recent_timestamp = str(int(time.time()) - 5 * 60)  # 5 minutes ago
        headers, body = _sign_request({}, secret, timestamp=recent_timestamp)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Replay Attack (Event Deduplication) Tests
# ---------------------------------------------------------------------------


class TestReplayAttackPrevention:
    """Tests for event ID deduplication to prevent replay attacks."""

    def test_duplicate_event_id_rejected(self, secure_client, store_with_secret):
        """Second request with same event ID should return 409."""
        secret = store_with_secret.get_cached_secret()
        event_id = str(uuid.uuid4())

        # First request should succeed
        headers1, body1 = _sign_request({}, secret, event_id=event_id)
        resp1 = secure_client.post("/sync", headers=headers1, content=body1)
        assert resp1.status_code == 200

        # Second request with same event ID should be rejected
        # Need new timestamp/signature but same event_id
        headers2, body2 = _sign_request({}, secret, event_id=event_id)
        resp2 = secure_client.post("/sync", headers=headers2, content=body2)
        assert resp2.status_code == 409
        assert "duplicate" in resp2.json()["detail"].lower()

    def test_different_event_ids_accepted(self, secure_client, store_with_secret):
        """Multiple requests with different event IDs should all succeed."""
        secret = store_with_secret.get_cached_secret()

        for _ in range(3):
            headers, body = _sign_request({}, secret)  # New event_id each time
            resp = secure_client.post("/sync", headers=headers, content=body)
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Rate Limiting Tests
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Tests for rate limiting protection."""

    def test_rate_limit_triggered(self, secure_client, store_with_secret):
        """Exceeding rate limit should return 429."""
        secret = store_with_secret.get_cached_secret()

        # Send requests until rate limited (default is 50/min)
        # We'll patch the rate limiter to use a smaller limit for testing
        from app import security

        original_limiter = security.rate_limiter

        try:
            # Create a rate limiter with very low limit for testing
            security.rate_limiter = security.RateLimiter(requests=3, window_seconds=60)

            # First 3 requests should pass
            for i in range(3):
                headers, body = _sign_request({}, secret)
                resp = secure_client.post("/sync", headers=headers, content=body)
                assert resp.status_code == 200, f"Request {i + 1} should pass"

            # 4th request should be rate limited
            headers, body = _sign_request({}, secret)
            resp = secure_client.post("/sync", headers=headers, content=body)
            assert resp.status_code == 429
            assert "rate" in resp.json()["detail"].lower()

        finally:
            security.rate_limiter = original_limiter


# ---------------------------------------------------------------------------
# Body Size Limit Tests
# ---------------------------------------------------------------------------


class TestBodySizeLimit:
    """Tests for request body size limits."""

    def test_oversized_body_rejected(self, secure_client, store_with_secret):
        """Request with body larger than 1MB should return 413."""
        secret = store_with_secret.get_cached_secret()

        # Create a payload larger than 1MB
        large_data = "x" * (2 * 1024 * 1024)  # 2MB
        payload = {"data": large_data}

        # Sign it (normally wouldn't work but we'll test the size check)
        headers, body = _sign_request(payload, secret)

        resp = secure_client.post("/sync", headers=headers, content=body)
        assert resp.status_code == 413
        assert "too large" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# IP Whitelist Tests
# ---------------------------------------------------------------------------


class TestIPWhitelist:
    """Tests for IP whitelist functionality."""

    def test_request_blocked_when_ip_not_whitelisted(self, store_with_secret):
        """When whitelist is configured, non-whitelisted IPs should be rejected."""
        from ipaddress import IPv4Network
        from app import config

        manager = SyncManager(store_with_secret)
        routes.set_dependencies(store_with_secret, manager)

        original_whitelist = list(config.IP_WHITELIST)

        try:
            # Modify whitelist in-place to only allow 10.0.0.0/8
            config.IP_WHITELIST.clear()
            config.IP_WHITELIST.append(IPv4Network("10.0.0.0/8"))

            # Patch IP to be outside the whitelist, and patch store
            with (
                patch.object(security, "get_client_ip", return_value="192.168.1.1"),
                patch.object(security, "store", store_with_secret),
            ):
                with TestClient(main_mod.app) as tc:
                    secret = store_with_secret.get_cached_secret()
                    headers, body = _sign_request({}, secret)

                    resp = tc.post("/sync", headers=headers, content=body)
                    assert resp.status_code == 403

        finally:
            config.IP_WHITELIST.clear()
            config.IP_WHITELIST.extend(original_whitelist)
            routes._store = None
            routes._sync_manager = None

    def test_request_allowed_when_ip_whitelisted(self, store_with_secret):
        """When whitelist includes the client IP, requests should be accepted."""
        from ipaddress import IPv4Network
        from app import config

        manager = SyncManager(store_with_secret)
        routes.set_dependencies(store_with_secret, manager)

        original_whitelist = list(config.IP_WHITELIST)

        try:
            # Modify whitelist in-place to include 192.168.0.0/16
            config.IP_WHITELIST.clear()
            config.IP_WHITELIST.append(IPv4Network("192.168.0.0/16"))

            # Patch IP to be inside the whitelist, and patch store
            with (
                patch.object(security, "get_client_ip", return_value="192.168.1.100"),
                patch.object(security, "store", store_with_secret),
            ):
                with TestClient(main_mod.app) as tc:
                    secret = store_with_secret.get_cached_secret()
                    headers, body = _sign_request({}, secret)

                    resp = tc.post("/sync", headers=headers, content=body)
                    assert resp.status_code == 200

        finally:
            config.IP_WHITELIST.clear()
            config.IP_WHITELIST.extend(original_whitelist)
            routes._store = None
            routes._sync_manager = None


# ---------------------------------------------------------------------------
# Multiple Endpoints Security Tests
# ---------------------------------------------------------------------------


class TestSecurityOnAllEndpoints:
    """Verify security is enforced on all protected endpoints."""

    def test_connect_config_requires_auth(self, secure_client):
        """POST /connect_config should require authentication."""
        resp = secure_client.post(
            "/connect_config",
            json={"netbox_url": "http://evil.com"},
        )
        assert resp.status_code == 400  # Missing headers

    def test_sync_config_requires_auth(self, secure_client):
        """POST /sync_config should require authentication."""
        resp = secure_client.post(
            "/sync_config",
            json={"config": {"key": "value"}},
        )
        assert resp.status_code == 400  # Missing headers

    def test_sync_requires_auth(self, secure_client):
        """POST /sync should require authentication."""
        resp = secure_client.post("/sync", json={})
        assert resp.status_code == 400  # Missing headers

    def test_get_endpoints_dont_require_auth(self, secure_client):
        """GET / (root) should not require webhook auth."""
        # Root endpoint is public
        resp = secure_client.get("/")
        assert resp.status_code == 200

    def test_config_get_endpoints_require_auth(self, secure_client):
        """GET /connect_config and /sync_config require webhook auth."""
        # These GETs require authentication (they return config data)
        resp = secure_client.get("/connect_config")
        assert resp.status_code == 400  # Missing headers

        resp = secure_client.get("/sync_config")
        assert resp.status_code == 400  # Missing headers
