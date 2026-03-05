"""Tests for webhook security validation.

Covers:
- Valid signature passes
- Invalid signature rejected
- Missing headers rejected
- Expired timestamp rejected
- Duplicate event ID rejected
- HMAC signature generation correctness
"""

import hashlib
import hmac
import time
from unittest.mock import patch


from app.security import (
    verify_hmac_signature,
    verify_timestamp_window,
    EventDeduplicator,
    RateLimiter,
)


class TestHMACSignature:
    def test_valid_signature(self):
        secret = "test_secret_123"
        timestamp = str(int(time.time()))
        body = b'{"key":"value"}'
        message = f"{timestamp}.{body.decode()}"
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

        assert verify_hmac_signature(timestamp, sig, body, secret=secret) is True

    def test_invalid_signature(self):
        secret = "test_secret_123"
        timestamp = str(int(time.time()))
        body = b'{"key":"value"}'

        assert verify_hmac_signature(timestamp, "bad_sig", body, secret=secret) is False

    def test_wrong_secret(self):
        secret = "correct_secret"
        timestamp = str(int(time.time()))
        body = b'{"key":"value"}'
        message = f"{timestamp}.{body.decode()}"
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

        assert verify_hmac_signature(timestamp, sig, body, secret="wrong_secret") is False

    def test_tampered_body(self):
        secret = "test_secret"
        timestamp = str(int(time.time()))
        original_body = b'{"key":"value"}'
        message = f"{timestamp}.{original_body.decode()}"
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()

        tampered_body = b'{"key":"tampered"}'
        assert verify_hmac_signature(timestamp, sig, tampered_body, secret=secret) is False

    def test_no_secret_available(self):
        """With no secret at all, verification should fail."""
        with patch("app.security.store") as mock_store:
            mock_store.get_cached_secret.return_value = None
            assert verify_hmac_signature("123", "sig", b"body") is False


class TestTimestampWindow:
    def test_current_timestamp_passes(self):
        ts = str(int(time.time()))
        assert verify_timestamp_window(ts) is True

    def test_expired_timestamp_fails(self):
        old_ts = str(int(time.time()) - 9999)
        assert verify_timestamp_window(old_ts, window_seconds=60) is False

    def test_future_timestamp_within_window(self):
        future_ts = str(int(time.time()) + 30)
        assert verify_timestamp_window(future_ts, window_seconds=60) is True

    def test_future_timestamp_outside_window(self):
        far_future = str(int(time.time()) + 9999)
        assert verify_timestamp_window(far_future, window_seconds=60) is False

    def test_invalid_timestamp(self):
        assert verify_timestamp_window("not-a-number") is False


class TestEventDeduplicator:
    def test_first_event_not_duplicate(self):
        dedup = EventDeduplicator(ttl_seconds=60)
        assert dedup.is_duplicate("evt-1") is False

    def test_same_event_is_duplicate(self):
        dedup = EventDeduplicator(ttl_seconds=60)
        dedup.is_duplicate("evt-1")
        assert dedup.is_duplicate("evt-1") is True

    def test_different_events_not_duplicate(self):
        dedup = EventDeduplicator(ttl_seconds=60)
        dedup.is_duplicate("evt-1")
        assert dedup.is_duplicate("evt-2") is False

    def test_expired_events_cleaned_up(self):
        dedup = EventDeduplicator(ttl_seconds=0)  # immediate expiry
        dedup.is_duplicate("evt-1")
        # After TTL=0, the event should be cleaned on next check
        import time

        time.sleep(0.01)
        assert dedup.is_duplicate("evt-1") is False


class TestRateLimiter:
    def test_under_limit_passes(self):
        rl = RateLimiter(requests=5, window_seconds=60)
        for _ in range(5):
            assert rl.is_rate_limited("127.0.0.1") is False

    def test_over_limit_blocked(self):
        rl = RateLimiter(requests=3, window_seconds=60)
        for _ in range(3):
            rl.is_rate_limited("127.0.0.1")
        assert rl.is_rate_limited("127.0.0.1") is True

    def test_different_ips_independent(self):
        rl = RateLimiter(requests=2, window_seconds=60)
        rl.is_rate_limited("10.0.0.1")
        rl.is_rate_limited("10.0.0.1")
        assert rl.is_rate_limited("10.0.0.1") is True
        assert rl.is_rate_limited("10.0.0.2") is False
