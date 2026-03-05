# NetBox-Zabbix Sync Webserver

A FastAPI-based webhook server that receives events and triggers synchronization between NetBox and Zabbix using the [netbox-zabbix-sync](https://github.com/your-repo/netbox-zabbix-sync) library.

## Features

- **Secure webhook endpoints** with HMAC-SHA256 signature validation
- **Replay attack protection** via timestamp validation and event deduplication
- **Rate limiting** per IP address
- **IP whitelisting** support
- **Encrypted credential storage** for NetBox/Zabbix connection details
- **Background sync processing** to avoid blocking webhook responses

## Installation

### Prerequisites

- Python 3.13+
- The `netbox-zabbix-sync` library

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/netbox-zabbix-sync-webserver.git
   cd netbox-zabbix-sync-webserver
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Generate a webhook secret:
   ```bash
   python main.py --generate-secret
   ```
   Save the output secret - you'll need it to sign webhook requests.

## Running the Server

Start the server with uvicorn:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

For development with auto-reload:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WEBHOOK_DB_PATH` | Path to SQLite database | `app_data.db` |
| `CONNECT_CONFIG_ENCRYPTION_KEY` | Fernet key for encrypting credentials | Auto-generated |
| `IP_WHITELIST` | Comma-separated CIDR ranges | `0.0.0.0/0` (allow all) |
| `DEBUG_MODE` | Enable detailed error messages | `true` |

### Encryption Key

Connection values (NetBox/Zabbix credentials) are encrypted with Fernet:

- **Recommended**: Set `CONNECT_CONFIG_ENCRYPTION_KEY` to a stable Fernet key
- **Fallback**: A local key file is created at `<WEBHOOK_DB_PATH>.key`

⚠️ Keep this key safe. Losing/changing it means existing encrypted values cannot be decrypted.

## API Endpoints

All endpoints (except `GET /`) require webhook authentication headers:
- `X-Signature`: HMAC-SHA256 signature of `{timestamp}.{body}`
- `X-Timestamp`: Unix timestamp (must be within 10 minutes)
- `X-Event-ID`: Unique identifier for replay protection

### `GET /`
Health check endpoint. No authentication required.

### `POST /sync`
Trigger a NetBox-Zabbix sync operation.

```bash
curl -X POST http://localhost:8000/sync \
    -H "Content-Type: application/json" \
    -H "X-Signature: <signature>" \
    -H "X-Timestamp: <timestamp>" \
    -H "X-Event-ID: <event-id>" \
    -d '{"device_filter": {"name": "SW01"}, "vm_filter": null}'
```

### `POST /connect_config` / `PATCH /connect_config`
Update connection configuration. Supports partial updates.

Supported keys:
- `netbox_url`: NetBox API URL
- `netbox_token`: NetBox API token
- `zabbix_url`: Zabbix API URL
- `zabbix_user`: Zabbix username
- `zabbix_password`: Zabbix password
- `zabbix_token`: Zabbix API token (alternative to password)

```bash
curl -X POST http://localhost:8000/connect_config \
    -H "Content-Type: application/json" \
    -H "X-Signature: <signature>" \
    -H "X-Timestamp: <timestamp>" \
    -H "X-Event-ID: <event-id>" \
    -d '{
        "netbox_url": "http://netbox:8000",
        "netbox_token": "nbt_xxxxxxxxx",
        "zabbix_url": "http://zabbix",
        "zabbix_user": "Admin",
        "zabbix_password": "zabbix"
    }'
```

### `GET /connect_config`
Retrieve current connection configuration (non-sensitive values only).

### `POST /sync_config` / `PATCH /sync_config`
Update sync configuration passed to the Sync class.

```bash
curl -X POST http://localhost:8000/sync_config \
    -H "Content-Type: application/json" \
    -H "X-Signature: <signature>" \
    -H "X-Timestamp: <timestamp>" \
    -H "X-Event-ID: <event-id>" \
    -d '{"config": {"clustering": "true", "template_cf": "zbx_template"}}'
```

### `GET /sync_config`
Retrieve current sync configuration.

### `DELETE /sync_config/{key}`
Delete a specific sync configuration key.

## Project Structure

```
├── main.py              # FastAPI app entry point
├── cli.py               # Command-line interface
├── app/                 # Application package
│   ├── __init__.py      # Package exports
│   ├── config.py        # Configuration constants
│   ├── routes.py        # API route definitions
│   ├── models.py        # Pydantic request/response models
│   ├── sync_manager.py  # Sync instance caching and management
│   ├── middleware.py    # Security dependency injection
│   ├── security.py      # HMAC validation, rate limiting, etc.
│   └── token_store.py   # SQLite storage for secrets and config
├── scripts/             # Ad-hoc testing scripts
│   ├── test_call.py     # Manual webhook testing
│   └── test_security_break.py
└── tests/               # Test suite
```

## Testing

Run the test suite:

```bash
pytest
```

With coverage:
```bash
pytest --cov=. --cov-report=term-missing
```

## Security

The webhook security layer provides:

1. **HMAC-SHA256 Signature Verification**: All requests must be signed
2. **Timestamp Validation**: Requests older than 10 minutes are rejected
3. **Event ID Deduplication**: Prevents replay attacks
4. **Rate Limiting**: 50 requests per minute per IP (configurable)
5. **IP Whitelisting**: Restrict access to specific IP ranges
6. **Body Size Limits**: Maximum 1MB request body

## License

MIT License - See LICENSE file for details.
