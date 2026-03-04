## Webhook secret storage

The webhook HMAC secret is stored in a local SQLite database (default: `webhook_secrets.db`).

Generate and store a new secret:

```bash
python main.py --generate-secret
```

If the database or secret is missing, the server will log a warning on startup and
signature verification will fail until a secret is created.

## Connection configuration storage

NetBox/Zabbix connection values are stored in the same SQLite database under
encrypted `connection_config` entries (not hardcoded in `main.py`).

Supported keys for `POST /connect_config`:

- `netbox_url`
- `netbox_token`
- `zabbix_url`
- `zabbix_user`
- `zabbix_password`
- `zabbix_token`

This endpoint uses the same webhook security dependency as `/sync`, so include
the required security headers (`X-Signature`, `X-Timestamp`, `X-Event-ID`).

### Example: update one value

```bash
curl -X POST http://localhost:8000/connect_config \
	-H "Content-Type: application/json" \
	-H "X-Signature: <signature>" \
	-H "X-Timestamp: <timestamp>" \
	-H "X-Event-ID: <event-id>" \
	-d '{
		"netbox_token": "nbt_xxxxxxxxxxxxxxxxx"
	}'
```

### Example: update multiple values

```bash
curl -X POST http://localhost:8000/connect_config \
	-H "Content-Type: application/json" \
	-H "X-Signature: <signature>" \
	-H "X-Timestamp: <timestamp>" \
	-H "X-Event-ID: <event-id>" \
	-d '{
		"netbox_url": "http://localhost:8000",
		"netbox_token": "nbt_xxxxxxxxxxxxxxxxx",
		"zabbix_url": "http://localhost",
		"zabbix_user": "Admin",
		"zabbix_password": "zabbix"
	}'
```

### Example: read current public config

`GET /connect_config` returns only non-sensitive fields (`netbox_url`,
`zabbix_url`, `zabbix_user`). Tokens/passwords are never returned.

```bash
curl -X GET http://localhost:8000/connect_config \
	-H "X-Signature: <signature>" \
	-H "X-Timestamp: <timestamp>" \
	-H "X-Event-ID: <event-id>"
```

## Encryption key

Connection values are encrypted with Fernet.

- Preferred: set `CONNECT_CONFIG_ENCRYPTION_KEY` to a stable Fernet key.
- Fallback: a local key file is created at `<WEBHOOK_DB_PATH>.key`.

Keep this key safe. Losing/changing it means existing encrypted values cannot be
decrypted.
