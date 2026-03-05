"""Configuration settings for the webhook server."""
import os
from ipaddress import IPv4Network

# Security Settings
WEBHOOK_DB_PATH = os.getenv("WEBHOOK_DB_PATH", "app_data.db")
WEBHOOK_SECRET_DEBUG = os.getenv("WEBHOOK_SECRET_DEBUG", "true").lower() == "true"

# Timestamp window for replay protection (seconds)
TIMESTAMP_WINDOW = 10 * 60  # 10 minutes

# Rate limiting
RATE_LIMIT_REQUESTS = 50  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

# Body size limit (1 MB)
MAX_BODY_SIZE = 1024 * 1024  # 1 MB in bytes

# IP Whitelisting (CIDR notation, 0.0.0.0/0 allows all)
IP_WHITELIST = os.getenv("IP_WHITELIST", "0.0.0.0/0").split(",")
IP_WHITELIST = [IPv4Network(ip.strip()) for ip in IP_WHITELIST]

# Debug mode (detailed error messages)
DEBUG_MODE = os.getenv("DEBUG_MODE", "true").lower() == "true"

# Header names
HEADER_SIGNATURE = "X-Signature"
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_EVENT_ID = "X-Event-ID"
