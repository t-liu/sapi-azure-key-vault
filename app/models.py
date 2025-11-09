"""
Pydantic models for request validation with Azure Key Vault limits
"""

from typing import Dict, List
from pydantic import BaseModel, Field, validator
from app.constants import Config


class PropertyItem(BaseModel):
    """Model for a single property item in POST/PUT requests"""

    environment: str
    keys_: str = Field(..., alias="keys")
    properties_: Dict[str, str] = Field(..., alias="properties")

    @validator("environment", check_fields=False)
    def validate_environment(cls, v):
        """Validate environment field"""
        if not v:
            raise ValueError("Environment cannot be empty")

        v = v.strip()
        if not v:
            raise ValueError("Environment cannot be empty")

        if len(v) > Config.MAX_ENVIRONMENT_LENGTH:
            raise ValueError(
                f"Environment cannot exceed {Config.MAX_ENVIRONMENT_LENGTH} characters"
            )

        if not all(c.isalnum() or c in "-_." for c in v):
            raise ValueError(
                "Environment contains invalid characters. Only alphanumeric, hyphens, underscores, and dots are allowed"
            )

        return v

    @validator("keys_", check_fields=False)
    def validate_keys(cls, v):
        """Validate keys field"""
        if not v or not v.strip():
            raise ValueError("Keys cannot be empty")

        v = v.strip()
        if not v:
            raise ValueError("Keys cannot be empty")

        if len(v) > Config.MAX_APP_KEY_LENGTH:
            raise ValueError(f"Keys cannot exceed {Config.MAX_APP_KEY_LENGTH} characters")

        if not all(c.isalnum() or c in "-_." for c in v):
            raise ValueError(
                "Keys contains invalid characters. Only alphanumeric, hyphens, underscores, and dots are allowed"
            )

        return v

    @validator("properties_", check_fields=False)
    def validate_properties(cls, v):
        """Validate properties dictionary with limits"""
        if not v:
            raise ValueError("Properties dictionary cannot be empty")

        # Limit number of properties per request
        if len(v) > Config.MAX_PROPERTIES_PER_REQUEST:
            raise ValueError(
                f"Too many properties ({len(v)}). Maximum {Config.MAX_PROPERTIES_PER_REQUEST} properties per request"
            )

        # Validate each property key and value
        for key, value in v.items():
            # Azure Key Vault secret name limit
            if len(key) > Config.MAX_SECRET_NAME_LENGTH:
                raise ValueError(
                    f"Property key too long: '{key[:20]}...' (max {Config.MAX_SECRET_NAME_LENGTH} characters)"
                )

            # Azure Key Vault secret value limit
            if len(value) > Config.MAX_SECRET_VALUE_LENGTH:
                raise ValueError(
                    f"Property value too long for key '{key}' (max {Config.MAX_SECRET_VALUE_LENGTH // 1000}KB/{Config.MAX_SECRET_VALUE_LENGTH} characters)"
                )

            # Property values cannot be empty
            if not value:
                raise ValueError(f"Property value cannot be empty for key '{key}'")

        return v

    class Config:
        allow_population_by_field_name = True
        allow_population_by_alias = True
        underscore_attrs_are_private = False


class PropertiesRequest(BaseModel):
    """Model for POST/PUT request body"""

    properties: List[PropertyItem]

    @validator("properties", check_fields=False)
    def validate_properties_list(cls, v):
        """Validate properties list size"""
        if len(v) < 1:
            raise ValueError("At least one property item is required")
        if len(v) > Config.MAX_ITEMS_PER_BATCH:
            raise ValueError(f"Cannot exceed {Config.MAX_ITEMS_PER_BATCH} items per batch")
        return v


class PropertyResponse(BaseModel):
    """Model for individual property response (used by GET endpoint)"""

    environment: str
    key: str
    properties: Dict[str, str]


class PropertySetResponse(BaseModel):
    """Model for POST/PUT operation responses"""

    environment: str
    key: str
    code: int
    message: str


class PropertiesResponse(BaseModel):
    """Model for GET response body"""

    responses: List[PropertyResponse]


class PropertiesSetResponse(BaseModel):
    """Model for POST/PUT response body"""

    responses: List[PropertySetResponse]


class DeleteResponse(BaseModel):
    """Model for DELETE operation responses"""

    environment: str
    key: str
    status_code: int
    message: str


class ErrorResponse(BaseModel):
    """Model for error responses"""

    error: str
    message: str
    status_code: int
