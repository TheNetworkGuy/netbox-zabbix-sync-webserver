"""Security utilities for webhook validation and protection."""
import hmac
import hashlib
import logging
import time
from datetime import datetime, timedelta
from ipaddress import IPv4Address
from collections import defaultdict
from typing import Callable, Optional
from fastapi import Request, HTTPException, status
from functools import wraps
import config
from token_store import store, SecretStoreError

# Configure logging
logger = logging.getLogger(__name__)


class EventDeduplicator:
    """In-memory event deduplication with TTL."""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.events = {}  # {event_id: timestamp}
        self.ttl = ttl_seconds
    
    def is_duplicate(self, event_id: str) -> bool:
        """Check if event ID is duplicate and still within TTL."""
        now = time.time()
        
        # Clean expired entries
        expired = [eid for eid, ts in self.events.items() if now - ts > self.ttl]
        for eid in expired:
            del self.events[eid]
        
        if event_id in self.events:
            return True
        
        self.events[event_id] = now
        return False


class RateLimiter:
    """Per-IP rate limiting."""
    
    def __init__(self, requests: int = 50, window_seconds: int = 60):
        self.requests = requests
        self.window = window_seconds
        self.requests_by_ip = defaultdict(list)  # {ip: [timestamp, ...]}
    
    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP has exceeded rate limit."""
        now = time.time()
        window_start = now - self.window
        
        # Clean old entries
        self.requests_by_ip[ip] = [
            ts for ts in self.requests_by_ip[ip] if ts > window_start
        ]
        
        if len(self.requests_by_ip[ip]) >= self.requests:
            return True
        
        self.requests_by_ip[ip].append(now)
        return False


# Global instances
event_dedup = EventDeduplicator(ttl_seconds=config.TIMESTAMP_WINDOW)
rate_limiter = RateLimiter(
    requests=config.RATE_LIMIT_REQUESTS,
    window_seconds=config.RATE_LIMIT_WINDOW
)


def verify_hmac_signature(
    timestamp: str,
    signature: str,
    body: bytes,
    secret: str | None = None
) -> bool:
    """Verify HMAC-SHA256 signature. Format: {timestamp}.{raw_body}"""
    try:
        try:
            secret_to_use = secret or store.get_cached_secret()
        except SecretStoreError as exc:
            logger.error("Webhook secret DB error: %s", exc)
            return False
        if not secret_to_use:
            logger.warning("No webhook secret available for signature verification")
            return False
        message = f"{timestamp}.{body.decode('utf-8')}"
        expected_signature = hmac.new(
            secret_to_use.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def verify_timestamp_window(timestamp_str: str, window_seconds: int = config.TIMESTAMP_WINDOW) -> bool:
    """Verify timestamp is within acceptable window."""
    try:
        timestamp = float(timestamp_str)
        current_time = time.time()
        time_diff = abs(current_time - timestamp)
        
        if time_diff > window_seconds:
            logger.warning(
                f"Timestamp outside window: diff={time_diff}s, window={window_seconds}s"
            )
            return False
        return True
    except (ValueError, TypeError) as e:
        logger.error(f"Timestamp parsing error: {e}")
        return False


def is_ip_whitelisted(ip: str, whitelist: list = config.IP_WHITELIST) -> bool:
    """Check if IP is in whitelist."""
    try:
        ip_addr = IPv4Address(ip)
        return any(ip_addr in network for network in whitelist)
    except Exception as e:
        logger.error(f"IP whitelisting error: {e}")
        return False


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, accounting for proxies."""
    # Check X-Forwarded-For header first (for proxied requests)
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    # Fall back to direct client
    if request.client:
        return request.client.host
    return "unknown"


async def validate_webhook_security(request: Request, body: bytes) -> dict:
    """
    Comprehensive webhook security validation.
    
    Returns: dict with validation results
    Raises: HTTPException if validation fails
    """
    errors = []
    client_ip = get_client_ip(request)
    
    # 1. Check body size
    if len(body) > config.MAX_BODY_SIZE:
        error_msg = f"Body too large: {len(body)} > {config.MAX_BODY_SIZE}"
        logger.error(f"Security: {error_msg} from {client_ip}")
        errors.append(error_msg)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=error_msg if config.DEBUG_MODE else "Request body too large"
        )
    
    # 2. Check IP whitelist
    if not is_ip_whitelisted(client_ip):
        error_msg = f"IP not whitelisted: {client_ip}"
        logger.warning(f"Security: {error_msg}")
        errors.append(error_msg)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=error_msg if config.DEBUG_MODE else "Access denied"
        )
    
    # 3. Check rate limit
    if rate_limiter.is_rate_limited(client_ip):
        error_msg = f"Rate limit exceeded for IP: {client_ip}"
        logger.warning(f"Security: {error_msg}")
        errors.append(error_msg)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error_msg if config.DEBUG_MODE else "Rate limit exceeded"
        )
    
    # 4. Check required headers
    signature = request.headers.get(config.HEADER_SIGNATURE)
    timestamp = request.headers.get(config.HEADER_TIMESTAMP)
    event_id = request.headers.get(config.HEADER_EVENT_ID)
    
    if not signature:
        error_msg = f"Missing {config.HEADER_SIGNATURE} header"
        logger.error(f"Security: {error_msg} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg if config.DEBUG_MODE else "Invalid request"
        )
    
    if not timestamp:
        error_msg = f"Missing {config.HEADER_TIMESTAMP} header"
        logger.error(f"Security: {error_msg} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg if config.DEBUG_MODE else "Invalid request"
        )
    
    if not event_id:
        error_msg = f"Missing {config.HEADER_EVENT_ID} header"
        logger.error(f"Security: {error_msg} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg if config.DEBUG_MODE else "Invalid request"
        )
    
    # 5. Verify timestamp window
    if not verify_timestamp_window(timestamp):
        error_msg = f"Timestamp outside acceptable window from {client_ip}"
        logger.warning(f"Security: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg if config.DEBUG_MODE else "Request expired"
        )
    
    # 6. Verify HMAC signature
    if not verify_hmac_signature(timestamp, signature, body):
        error_msg = f"Invalid signature from {client_ip}"
        logger.error(f"Security: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg if config.DEBUG_MODE else "Unauthorized"
        )
    
    # 7. Check for duplicate event (replay attack)
    if event_dedup.is_duplicate(event_id):
        error_msg = f"Duplicate event ID detected: {event_id} from {client_ip}"
        logger.warning(f"Security: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=error_msg if config.DEBUG_MODE else "Duplicate event"
        )
    
    logger.info(f"Security validation passed for {event_id} from {client_ip}")
    
    return {
        "client_ip": client_ip,
        "event_id": event_id,
        "timestamp": timestamp,
        "valid": True
    }
