"""
Key Vault Service Layer
Handles all interactions with Azure Key Vault
"""

import os
import logging
import threading
import base64
from typing import Dict
from datetime import datetime, timedelta
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import (
    ResourceNotFoundError,
    ServiceRequestError,
    HttpResponseError,
)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from app.constants import Config, LogMessages

logger = logging.getLogger(__name__)


class KeyVaultService:
    """Service class for Azure Key Vault operations"""

    def __init__(self, cache_ttl_minutes: int = Config.CACHE_TTL_MINUTES):
        """
        Initialize Key Vault client with DefaultAzureCredential

        Args:
            cache_ttl_minutes: Cache time-to-live in minutes (default from Config)
        """
        self.key_vault_url = os.getenv("AZURE_KEY_VAULT_URL")

        if not self.key_vault_url:
            raise ValueError("AZURE_KEY_VAULT_URL environment variable is not set")

        self.credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=self.key_vault_url, credential=self.credential)

        # Initialize cache with thread safety
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = timedelta(minutes=cache_ttl_minutes)

        logger.info(
            f"KeyVaultService initialized with vault: {self.key_vault_url}, cache TTL: {cache_ttl_minutes}m"
        )

    def _generate_secret_name(self, env: str, app_key: str, property_key: str) -> str:
        """
        Generate a standardized secret name using base64url encoding for property keys
        Format: {env}--{app_key}--{base64url_property_key}
        Azure Key Vault only allows alphanumeric and hyphens

        This ensures all property key characters are preserved (reversible encoding)
        and prevents naming conflicts from character replacement.
        """
        # Validate inputs contain only safe characters
        if not all(c.isalnum() or c in "-_." for c in env):
            raise ValueError(
                f"Invalid characters in environment: '{env}'. Only alphanumeric, hyphens, underscores, and dots allowed"
            )
        if not all(c.isalnum() or c in "-_." for c in app_key):
            raise ValueError(
                f"Invalid characters in app_key: '{app_key}'. Only alphanumeric, hyphens, underscores, and dots allowed"
            )

        # Replace underscores and dots with hyphens for env and app_key
        safe_env = env.replace("_", "-").replace(".", "-")
        safe_app_key = app_key.replace("_", "-").replace(".", "-")

        # Use base64url encoding for property key to preserve ALL characters
        # base64url is safe for URLs/filenames: uses - and _ instead of + and /
        encoded_key = (
            base64.urlsafe_b64encode(property_key.encode("utf-8")).decode("ascii").rstrip("=")
        )  # Remove padding

        secret_name = f"{safe_env}{Config.SECRET_NAME_SEPARATOR}{safe_app_key}{Config.SECRET_NAME_SEPARATOR}{encoded_key}"

        # Azure Key Vault name limit
        if len(secret_name) > Config.MAX_SECRET_NAME_LENGTH:
            raise ValueError(
                f"Secret name too long: '{secret_name[:50]}...' ({len(secret_name)} chars, max {Config.MAX_SECRET_NAME_LENGTH})"
            )

        return secret_name

    def _decode_property_key(self, encoded_key: str) -> str:
        """
        Decode base64url encoded property key back to original
        Adds padding if needed and decodes from base64url
        """
        # Add padding if needed (base64 requires length to be multiple of 4)
        padding = 4 - len(encoded_key) % 4
        if padding != 4:
            encoded_key += "=" * padding

        try:
            return base64.urlsafe_b64decode(encoded_key.encode("ascii")).decode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to decode property key '{encoded_key}': {e}")
            # Fallback for legacy keys (old format without base64 encoding)
            return encoded_key.replace("-", ".")

    @retry(
        stop=stop_after_attempt(Config.RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(
            multiplier=Config.RETRY_MULTIPLIER,
            min=Config.RETRY_MIN_WAIT_SECONDS,
            max=Config.RETRY_MAX_WAIT_SECONDS,
        ),
        retry=retry_if_exception_type((ServiceRequestError, HttpResponseError)),
        reraise=True,
    )
    def get_properties(self, env: str, app_key: str) -> Dict[str, str]:
        """
        Retrieve all properties for a given environment and app key
        Uses thread-safe caching to prevent repeated Key Vault list operations
        Retries up to 3 times with exponential backoff on transient errors

        Args:
            env: Environment name (e.g., 'qa', 'prod')
            app_key: Application key identifier

        Returns:
            Dictionary of property key-value pairs
        """
        cache_key = f"{env}:{app_key}"

        # Check cache with thread safety
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached:
                cache_age = datetime.now() - cached["timestamp"]
                if cache_age < self._cache_ttl:
                    logger.info(LogMessages.CACHE_HIT.format(cache_key=cache_key, age=cache_age.seconds))
                    return cached["data"].copy()
                else:
                    logger.debug(f"Cache expired for {cache_key} (age: {cache_age.seconds}s)")

        # Cache miss or expired - fetch from Key Vault
        logger.info(LogMessages.CACHE_MISS.format(cache_key=cache_key))
        properties = {}
        prefix = f"{env}--{app_key}--"

        try:
            # List all secrets with the matching prefix
            secret_properties = self.client.list_properties_of_secrets()

            for secret_property in secret_properties:
                if secret_property.name.startswith(prefix):
                    try:
                        secret = self.client.get_secret(secret_property.name)
                        # Extract the encoded property key from the secret name
                        encoded_property_key = secret_property.name[len(prefix) :]
                        # Decode base64url back to original property key
                        original_key = self._decode_property_key(encoded_property_key)
                        properties[original_key] = secret.value
                    except ResourceNotFoundError:
                        logger.warning(f"Secret {secret_property.name} not found")
                        continue

            # Update cache with thread safety
            with self._cache_lock:
                self._cache[cache_key] = {"data": properties.copy(), "timestamp": datetime.now()}

            logger.info(
                f"Retrieved {len(properties)} properties for {env}/{app_key}, cached for {self._cache_ttl.seconds}s"
            )
            return properties

        except Exception as e:
            logger.error(f"Error retrieving properties for {env}/{app_key}: {str(e)}")
            raise

    @retry(
        stop=stop_after_attempt(Config.RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(
            multiplier=Config.RETRY_MULTIPLIER,
            min=Config.RETRY_MIN_WAIT_SECONDS,
            max=Config.RETRY_MAX_WAIT_SECONDS,
        ),
        retry=retry_if_exception_type((ServiceRequestError, HttpResponseError)),
        reraise=True,
    )
    def set_properties(self, env: str, app_key: str, properties: Dict[str, str]) -> Dict[str, str]:
        """
        Set multiple properties for a given environment and app key
        Invalidates cache to ensure fresh data is retrieved
        Retries up to 3 times with exponential backoff on transient errors

        Args:
            env: Environment name
            app_key: Application key identifier
            properties: Dictionary of property key-value pairs to set

        Returns:
            Dictionary of all properties after setting
        """
        try:
            for property_key, property_value in properties.items():
                secret_name = self._generate_secret_name(env, app_key, property_key)
                self.client.set_secret(secret_name, property_value)
                logger.info(f"Set secret: {secret_name}")

            # Invalidate cache for this env/app_key
            cache_key = f"{env}:{app_key}"
            with self._cache_lock:
                if cache_key in self._cache:
                    del self._cache[cache_key]
                    logger.debug(LogMessages.CACHE_INVALIDATED.format(cache_key=cache_key))

            # Return all properties after setting (will refresh cache)
            return self.get_properties(env, app_key)

        except Exception as e:
            logger.error(f"Error setting properties for {env}/{app_key}: {str(e)}")
            raise

    @retry(
        stop=stop_after_attempt(Config.RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(
            multiplier=Config.RETRY_MULTIPLIER,
            min=Config.RETRY_MIN_WAIT_SECONDS,
            max=Config.RETRY_MAX_WAIT_SECONDS,
        ),
        retry=retry_if_exception_type((ServiceRequestError, HttpResponseError)),
        reraise=True,
    )
    def delete_properties(self, env: str, app_key: str) -> int:
        """
        Delete all properties for a given environment and app key
        Invalidates cache to ensure consistency
        Retries up to 3 times with exponential backoff on transient errors

        Args:
            env: Environment name
            app_key: Application key identifier

        Returns:
            Number of properties deleted
        """
        prefix = f"{env}{Config.SECRET_NAME_SEPARATOR}{app_key}{Config.SECRET_NAME_SEPARATOR}"
        deleted_count = 0

        try:
            secret_properties = self.client.list_properties_of_secrets()

            for secret_property in secret_properties:
                if secret_property.name.startswith(prefix):
                    try:
                        poller = self.client.begin_delete_secret(secret_property.name)
                        poller.wait()
                        deleted_count += 1
                        logger.info(f"Deleted secret: {secret_property.name}")
                    except ResourceNotFoundError:
                        logger.warning(f"Secret {secret_property.name} not found for deletion")
                        continue

            # Invalidate cache for this env/app_key
            cache_key = f"{env}:{app_key}"
            with self._cache_lock:
                if cache_key in self._cache:
                    del self._cache[cache_key]
                    logger.debug(LogMessages.CACHE_INVALIDATED.format(cache_key=cache_key))

            logger.info(f"Deleted {deleted_count} properties for {env}/{app_key}")
            return deleted_count

        except Exception as e:
            logger.error(f"Error deleting properties for {env}/{app_key}: {str(e)}")
            raise

    def clear_cache(self) -> None:
        """Clear all cached data (useful for testing or manual cache invalidation)"""
        with self._cache_lock:
            cache_size = len(self._cache)
            self._cache.clear()
            logger.info(LogMessages.CACHE_CLEARED.format(count=cache_size))