"""Dependencies for webhook security validation."""
import logging
from fastapi import Request, Depends, HTTPException
from security import validate_webhook_security

logger = logging.getLogger(__name__)


async def webhook_security_dependency(request: Request) -> dict:
    """
    Dependency for validating webhook security on protected endpoints.
    
    This runs before endpoint logic and Pydantic validation.
    Validates:
    - HMAC-SHA256 signature
    - Timestamp freshness (replay protection)
    - Event ID deduplication
    - Rate limiting per IP
    - IP whitelisting
    - Body size limits
    
    Returns: dict with security validation info (client_ip, event_id, etc.)
    Raises: HTTPException if validation fails
    """
    body = await request.body()
    security_info = await validate_webhook_security(request, body)
    return security_info
