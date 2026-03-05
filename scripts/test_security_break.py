"""
Security test script to attempt to break the webhook security.

This script tests various attack vectors and security measures:
- Rate limiting (too many requests per minute)
- Body size limits (oversized payloads)
- Timestamp validation (expired/future timestamps)
- Invalid signatures (tampered data)
- Missing/invalid headers
- Replay attacks (duplicate event IDs)
- Signature verification

Usage:
    python test_security_break.py

Make sure the server is running:
    uvicorn main:app --reload --port 8001
"""
import os
import sys
import requests
import hmac
import hashlib
import time
import json
import uuid
from typing import Optional
from pathlib import Path

# Add project root to path for importing app modules
PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from app.token_store import store, SecretStoreError


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
    print("❌ No webhook secret found. Generate one with: python main.py --generate-secret")
    sys.exit(1)


def generate_webhook_signature(
    timestamp: str,
    body: bytes,
    secret: str
) -> str:
    """Generate HMAC-SHA256 signature."""
    message = f"{timestamp}.{body.decode('utf-8')}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def send_raw_request(
    url: str = "http://localhost:8001/sync",
    headers: Optional[dict] = None,
    body: bytes = b"",
    verbose: bool = False
) -> requests.Response | None:
    """Send a raw request with custom headers and body."""
    if headers is None:
        headers = {}
    
    try:
        response = requests.post(url, headers=headers, data=body, timeout=5)
        
        if verbose and response.status_code >= 400:
            try:
                detail = response.json().get('detail', response.text)
                print(f"   Response: {detail}")
            except Exception:
                print(f"   Response: {response.text[:100]}")
        
        return response
    except Exception as e:
        print(f"   ❌ Connection error: {e}")
        return None


def test_rate_limiting(url: str = "http://localhost:8001/sync"):
    """Test rate limiting by sending too many requests."""
    print("\n" + "=" * 60)
    print("TEST: RATE LIMITING (50 req/min)")
    print("=" * 60)
    
    print("Sending 60 requests rapidly to exceed rate limit...")
    success_count = 0
    rate_limited_count = 0
    other_errors = 0
    
    secret = load_secret()
    for i in range(60):
        timestamp = str(int(time.time()))
        data = {"data": {"test": f"request_{i}"}}
        body = json.dumps(data).encode()
        signature = generate_webhook_signature(timestamp, body, secret)
        
        headers = {
            "Content-Type": "application/json",
            "X-Signature": signature,
            "X-Timestamp": timestamp,
            "X-Event-ID": str(uuid.uuid4())
        }
        
        response = send_raw_request(url, headers, body, verbose=False)
        if response:
            if response.status_code == 200:
                success_count += 1
            elif response.status_code == 429:
                rate_limited_count += 1
                if rate_limited_count == 1:
                    print(f"   ✓ Rate limit triggered at request {i+1}: {response.json()['detail']}")
            else:
                other_errors += 1
        
        # Don't add delays to actually trigger the rate limit
    
    if rate_limited_count > 0:
        print(f"   ✓ Results: {success_count} accepted, {rate_limited_count} rate limited")
    else:
        print(f"   ❌ Results: {success_count} accepted, {rate_limited_count} rate limited (expected > 0 rate limited)")


def test_oversized_body(url: str = "http://localhost:8001/sync"):
    """Test body size limit (1 MB)."""
    print("\n" + "=" * 60)
    print("TEST: BODY SIZE LIMIT (1 MB)")
    print("=" * 60)
    
    # Create a payload larger than 1 MB
    large_data = "x" * (2 * 1024 * 1024)  # 2 MB
    body = json.dumps({"data": large_data}, separators=(',', ':')).encode()
    
    timestamp = str(int(time.time()))
    secret = load_secret()
    signature = generate_webhook_signature(timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending 2 MB payload...")
    response = send_raw_request(url, headers, body, verbose=True)
    
    if response:
        if response.status_code == 413:
            print("   ✓ Request rejected (413)")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_expired_timestamp(url: str = "http://localhost:8001/sync"):
    """Test timestamp validation (>10 minute window)."""
    print("\n" + "=" * 60)
    print("TEST: EXPIRED TIMESTAMP (>10 min old)")
    print("=" * 60)
    
    # Use timestamp from 15 minutes ago (outside 10 min window)
    old_timestamp = str(int(time.time()) - (15 * 60))
    data = {"data": {"test": "old_request"}}
    body = json.dumps(data, separators=(',', ':')).encode()
    secret = load_secret()
    signature = generate_webhook_signature(old_timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": old_timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request with timestamp from 15 minutes ago...")
    response = send_raw_request(url, headers, body, verbose=True)
    
    if response:
        if response.status_code == 401:
            print("   ✓ Request rejected (401)")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_future_timestamp(url: str = "http://localhost:8001/sync"):
    """Test timestamp validation (future timestamp)."""
    print("\n" + "=" * 60)
    print("TEST: FUTURE TIMESTAMP (>10 min ahead)")
    print("=" * 60)
    
    # Use timestamp from 15 minutes in the future
    future_timestamp = str(int(time.time()) + (15 * 60))
    data = {"test": "future_request"}
    body = json.dumps(data).encode()
    secret = load_secret()
    signature = generate_webhook_signature(future_timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": future_timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request with timestamp 15 minutes in the future...")
    response = send_raw_request(url, headers, body)
    
    if response:
        if response.status_code == 401:
            print(f"   ✓ Request rejected (401): {response.json()['detail']}")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_invalid_signature(url: str = "http://localhost:8001/sync"):
    """Test signature verification with tampered data."""
    print("\n" + "=" * 60)
    print("TEST: INVALID SIGNATURE (tampered data)")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    data = {"data": {"test": "tampered"}}
    body = json.dumps(data, separators=(',', ':')).encode()
    
    # Generate signature with wrong secret
    bad_signature = generate_webhook_signature(timestamp, body, "wrong-secret")
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": bad_signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request with signature from wrong secret...")
    response = send_raw_request(url, headers, body, verbose=True)
    
    if response:
        if response.status_code == 401:
            print("   ✓ Request rejected (401)")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_missing_signature_header(url: str = "http://localhost:8001/sync"):
    """Test missing signature header."""
    print("\n" + "=" * 60)
    print("TEST: MISSING SIGNATURE HEADER")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    data = {"data": {"test": "no_signature"}}
    body = json.dumps(data, separators=(',', ':')).encode()
    
    headers = {
        "Content-Type": "application/json",
        # Missing X-Signature
        "X-Timestamp": timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request without X-Signature header...")
    response = send_raw_request(url, headers, body, verbose=True)
    
    if response:
        if response.status_code == 400:
            print("   ✓ Request rejected (400)")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_missing_timestamp_header(url: str = "http://localhost:8001/sync"):
    """Test missing timestamp header."""
    print("\n" + "=" * 60)
    print("TEST: MISSING TIMESTAMP HEADER")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    data = {"test": "no_timestamp"}
    body = json.dumps(data).encode()
    secret = load_secret()
    signature = generate_webhook_signature(timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        # Missing X-Timestamp
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request without X-Timestamp header...")
    response = send_raw_request(url, headers, body)
    
    if response:
        if response.status_code == 400:
            print(f"   ✓ Request rejected (400): {response.json()['detail']}")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_missing_event_id_header(url: str = "http://localhost:8001/sync"):
    """Test missing event ID header."""
    print("\n" + "=" * 60)
    print("TEST: MISSING EVENT-ID HEADER")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    data = {"test": "no_event_id"}
    body = json.dumps(data).encode()
    secret = load_secret()
    signature = generate_webhook_signature(timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        # Missing X-Event-ID
    }
    
    print("Sending request without X-Event-ID header...")
    response = send_raw_request(url, headers, body)
    
    if response:
        if response.status_code == 400:
            print(f"   ✓ Request rejected (400): {response.json()['detail']}")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


def test_replay_attack(url: str = "http://localhost:8001/sync"):
    """Test duplicate event ID detection (replay attack)."""
    print("\n" + "=" * 60)
    print("TEST: REPLAY ATTACK (duplicate event ID)")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    event_id = str(uuid.uuid4())
    data = {"data": {"test": "replay"}}
    body = json.dumps(data, separators=(',', ':')).encode()
    secret = load_secret()
    signature = generate_webhook_signature(timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Event-ID": event_id
    }
    
    print(f"Sending first request with event ID: {event_id}")
    response1 = send_raw_request(url, headers, body, verbose=False)
    
    if response1:
        if response1.status_code == 200:
            print("   ✓ First request accepted (200)")
        else:
            print(f"   ❌ First request failed ({response1.status_code})")
    
    # Send exact same request again (replay attack)
    print("\nSending duplicate request with same event ID (replay attack)...")
    response2 = send_raw_request(url, headers, body, verbose=True)
    
    if response2:
        if response2.status_code == 409:
            print("   ✓ Replay attack blocked (409)")
        else:
            print(f"   ❌ Replay attack not blocked! Status: {response2.status_code}")


def test_tampered_payload(url: str = "http://localhost:8001/sync"):
    """Test signature verification with modified payload."""
    print("\n" + "=" * 60)
    print("TEST: TAMPERED PAYLOAD (sig from different data)")
    print("=" * 60)
    
    timestamp = str(int(time.time()))
    original_data = {"test": "original"}
    original_body = json.dumps(original_data).encode()
    
    # Sign the original data
    secret = load_secret()
    signature = generate_webhook_signature(timestamp, original_body, secret)
    
    # But send modified data
    modified_data = {"test": "modified"}
    modified_body = json.dumps(modified_data).encode()
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,  # Signature from original data
        "X-Timestamp": timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print(f"Signing original data: {original_data}")
    print(f"Sending modified data: {modified_data}")
    response = send_raw_request(url, headers, modified_body)
    
    if response:
        if response.status_code == 401:
            print(f"   ✓ Tampered payload rejected (401): {response.json()['detail']}")
        else:
            print(f"   ❌ Tampered payload not rejected! Status: {response.status_code}")


def test_invalid_timestamp_format(url: str = "http://localhost:8001/sync"):
    """Test invalid timestamp format."""
    print("\n" + "=" * 60)
    print("TEST: INVALID TIMESTAMP FORMAT")
    print("=" * 60)
    
    bad_timestamp = "not-a-timestamp"
    data = {"test": "bad_timestamp"}
    body = json.dumps(data).encode()
    secret = load_secret()
    signature = generate_webhook_signature(bad_timestamp, body, secret)
    
    headers = {
        "Content-Type": "application/json",
        "X-Signature": signature,
        "X-Timestamp": bad_timestamp,
        "X-Event-ID": str(uuid.uuid4())
    }
    
    print("Sending request with invalid timestamp format...")
    response = send_raw_request(url, headers, body)
    
    if response:
        if response.status_code == 401:
            print(f"   ✓ Request rejected (401): {response.json()['detail']}")
        else:
            print(f"   ❌ Request not rejected! Status: {response.status_code}")


if __name__ == "__main__":
    import sys
    
    # Check if server is running
    try:
        response = requests.get("http://localhost:8001/", timeout=2)
        print("✓ Server is running\n")
    except requests.exceptions.ConnectionError:
        print("❌ Error: Server is not running!")
        print("   Start the server with: uvicorn main:app --reload --port 8001")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Connection error: {e}")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("WEBHOOK SECURITY BREACH TESTS")
    print("=" * 60)
    print("Testing various attack vectors and security measures...\n")
    
    # Run all security tests
    test_rate_limiting()
    test_oversized_body()
    test_expired_timestamp()
    test_future_timestamp()
    test_invalid_signature()
    test_missing_signature_header()
    test_missing_timestamp_header()
    test_missing_event_id_header()
    test_replay_attack()
    test_tampered_payload()
    test_invalid_timestamp_format()
    
    print("\n" + "=" * 60)
    print("SECURITY TEST COMPLETE")
    print("=" * 60)
