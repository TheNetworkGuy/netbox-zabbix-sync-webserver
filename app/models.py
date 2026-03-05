"""Pydantic models for API request/response schemas."""

from pydantic import BaseModel, Field


class SyncPayload(BaseModel):
    """Schema for incoming sync webhook data."""

    device_filter: dict | None = None
    vm_filter: dict | None = None
    timestamp: str | None = None


class ConnectionConfigPayload(BaseModel):
    """Schema for connection configuration updates."""

    netbox_url: str | None = Field(None, description="NetBox API URL")
    netbox_token: str | None = Field(None, description="NetBox API token")
    zabbix_url: str | None = Field(None, description="Zabbix API URL")
    zabbix_user: str | None = Field(None, description="Zabbix username")
    zabbix_password: str | None = Field(None, description="Zabbix password")
    zabbix_token: str | None = Field(None, description="Zabbix API token (alternative to password)")


class ConnectionConfigResponse(BaseModel):
    """Schema for connection configuration response."""

    status: str
    message: str
    updated_keys: list[str] | None = None


class SyncConfigPayload(BaseModel):
    """Schema for sync configuration updates."""

    config: dict[str, str] = Field(..., description="Sync configuration key-value pairs")


class SyncConfigResponse(BaseModel):
    """Schema for sync configuration response."""

    status: str
    message: str
    updated_keys: list[str] | None = None
