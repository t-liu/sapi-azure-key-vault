"""
Pydantic models for request validation with Azure Key Vault limits
"""

from typing import Dict, List
from pydantic import BaseModel, Field, field_validator
from app.constants import Config


class PropertyItem(BaseModel):
    """Model for a single property item in POST/PUT requests"""

    environment: str = Field(
        ...,
        min_length=1,
        max_length=Config.MAX_ENVIRONMENT_LENGTH,
        description=f"Environment name (max {Config.MAX_ENVIRONMENT_LENGTH} chars)",
    )
    key: str = Field(
        ...,
        min_length=1,
        max_length=Config.MAX_APP_KEY_LENGTH,
        description=f"Application key (max {Config.MAX_APP_KEY_LENGTH} chars)",
    )
    properties: Dict[str, str] = Field(..., description="Key-value pairs of properties")

    @field_validator("environment", "key")
    @classmethod
    def validate_alphanumeric(cls, v):
        """Validate environment and key contain only safe characters"""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")

        # Allow alphanumeric, hyphens, underscores, dots
        if not all(c.isalnum() or c in "-_." for c in v):
            raise ValueError(
                "Field contains invalid characters. Only alphanumeric, hyphens, underscores, and dots are allowed"
            )

        return v.strip()

    @field_validator("properties")
    @classmethod
    def validate_properties(cls, v):
        """Validate properties dictionary with Azure Key Vault limits"""
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


class PropertiesRequest(BaseModel):
    """Model for POST/PUT request body"""

    properties: List[PropertyItem] = Field(
        ...,
        min_length=1,
        max_length=Config.MAX_ITEMS_PER_BATCH,
        description=f"List of property items (max {Config.MAX_ITEMS_PER_BATCH})",
    )


class PropertyResponse(BaseModel):
    """Model for individual property response"""

    env: str
    appKey: str
    properties: Dict[str, str]


class PropertiesResponse(BaseModel):
    """Model for response body"""

    responses: List[PropertyResponse]


class DeleteResponse(BaseModel):
    """Model for DELETE operation responses"""

    message: str
    env: str
    appKey: str
    deleted_count: int


class ErrorResponse(BaseModel):
    """Model for error responses"""

    error: str
    message: str
    status_code: int
