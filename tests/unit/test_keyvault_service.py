"""
Unit tests for KeyVaultService
"""

import os
import pytest
import time
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from azure.keyvault.secrets import SecretClient, SecretProperties
from azure.core.exceptions import ResourceNotFoundError
from app.keyvault_service import KeyVaultService


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables"""
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://test-vault.vault.azure.net/")


@pytest.fixture
def mock_secret_client():
    """Create a mock SecretClient"""
    return Mock(spec=SecretClient)


class TestKeyVaultService:
    """Test KeyVaultService class"""

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_initialization(self, mock_client_class, mock_credential, mock_env_vars):
        """Test KeyVaultService initialization"""
        service = KeyVaultService()
        assert service.key_vault_url == "https://test-vault.vault.azure.net/"
        mock_credential.assert_called_once()
        mock_client_class.assert_called_once()

    def test_initialization_without_url_fails(self, monkeypatch):
        """Test that initialization fails without AZURE_KEY_VAULT_URL"""
        monkeypatch.delenv("AZURE_KEY_VAULT_URL", raising=False)
        with pytest.raises(ValueError, match="AZURE_KEY_VAULT_URL"):
            KeyVaultService()

    def test_generate_secret_name(self, mock_env_vars):
        """Test secret name generation with dot to hyphen conversion"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            name = service._generate_secret_name("qa", "test-app", "api.key")
            # Format: {env}--{app_key}--{property_key} with dots → hyphens
            assert name == "qa--test-app--api-key"

    def test_generate_secret_name_replaces_special_chars(self, mock_env_vars):
        """Test that env, app_key, and property_key special characters are replaced"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            name = service._generate_secret_name("qa_env", "test.app", "api.key")
            # All dots and underscores replaced with hyphens
            assert name == "qa-env--test-app--api-key"

    def test_generate_secret_name_validates_env(self, mock_env_vars):
        """Test that invalid characters in environment raise ValueError"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            with pytest.raises(ValueError, match="Invalid characters in environment"):
                service._generate_secret_name("qa@prod", "test-app", "api.key")

    def test_generate_secret_name_validates_app_key(self, mock_env_vars):
        """Test that invalid characters in app_key raise ValueError"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            with pytest.raises(ValueError, match="Invalid characters in app_key"):
                service._generate_secret_name("qa", "test/app", "api.key")

    def test_generate_secret_name_validates_property_key(self, mock_env_vars):
        """Test that invalid characters in property_key raise ValueError"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            with pytest.raises(ValueError, match="Invalid characters in property_key"):
                service._generate_secret_name("qa", "test-app", "api@key")

    def test_generate_secret_name_checks_length(self, mock_env_vars):
        """Test that secret names exceeding 127 chars raise ValueError"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            # Create a very long property key that will exceed 127 chars
            # Format: qa--test-app--{property_key}
            # qa--test-app-- = 14 chars, so need property_key to be > 113 chars
            long_key = "a" * 115
            with pytest.raises(ValueError, match="Secret name too long.*max 127"):
                service._generate_secret_name("qa", "test-app", long_key)

    def test_extract_property_key(self, mock_env_vars):
        """Test extracting original property key from secret name"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            secret_name = "qa--test-app--api-key"
            original_key = service._extract_property_key(secret_name, "qa", "test-app")
            # Should convert hyphens back to dots
            assert original_key == "api.key"

    def test_extract_property_key_with_underscores(self, mock_env_vars):
        """Test extracting property key that had underscores (converted to hyphens)"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            # When stored: "database_name.host" → "database-name-host"
            secret_name = "qa--test-app--database-name-host"
            original_key = service._extract_property_key(secret_name, "qa", "test-app")
            # Converts all hyphens back to dots
            assert original_key == "database.name.host"

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_get_properties_success(self, mock_client_class, mock_credential, mock_env_vars):
        """Test successful property retrieval"""
        # Setup
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties with prefix matching
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--https-port"

        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--db-password"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]

        # Mock get_secret responses
        mock_secret1 = Mock()
        mock_secret1.value = "443"
        mock_secret2 = Mock()
        mock_secret2.value = "secret123"

        mock_client.get_secret.side_effect = [mock_secret1, mock_secret2]

        # Test
        service = KeyVaultService()
        properties = service.get_properties("qa", "test-app")

        # Assert - should extract property keys without prefix
        assert "https.port" in properties
        assert properties["https.port"] == "443"
        assert "db.password" in properties
        assert properties["db.password"] == "secret123"

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_get_properties_filters_by_prefix(
        self, mock_client_class, mock_credential, mock_env_vars
    ):
        """Test that get_properties only returns secrets matching the env/app_key prefix"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock multiple secrets with different prefixes
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--key1"

        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--other-app--key2"

        secret_prop3 = Mock(spec=SecretProperties)
        secret_prop3.name = "prod--test-app--key3"

        mock_client.list_properties_of_secrets.return_value = [
            secret_prop1,
            secret_prop2,
            secret_prop3,
        ]

        # Mock get_secret response (only called for matching prefix)
        mock_secret1 = Mock()
        mock_secret1.value = "value1"
        mock_client.get_secret.return_value = mock_secret1

        # Test - query only qa/test-app
        service = KeyVaultService()
        properties = service.get_properties("qa", "test-app")

        # Should only have key1 (matching qa--test-app prefix)
        assert properties == {"key1": "value1"}
        # Should only call get_secret once (for the matching secret)
        mock_client.get_secret.assert_called_once()

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_get_properties_empty_result(self, mock_client_class, mock_credential, mock_env_vars):
        """Test get_properties with no matching secrets"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client
        mock_client.list_properties_of_secrets.return_value = []

        service = KeyVaultService()
        properties = service.get_properties("qa", "nonexistent-app")

        assert properties == {}

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_set_properties_success(self, mock_client_class, mock_credential, mock_env_vars):
        """Test successful property setting"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock list_properties for the final get_properties call
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--api-key"

        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--timeout"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]

        # Mock get_secret responses
        mock_secret1 = Mock()
        mock_secret1.value = "secret123"
        mock_secret2 = Mock()
        mock_secret2.value = "30"

        mock_client.get_secret.side_effect = [mock_secret1, mock_secret2]

        service = KeyVaultService()
        properties_to_set = {"api.key": "secret123", "timeout": "30"}

        result = service.set_properties("qa", "test-app", properties_to_set)

        # Should return properties without the prefix
        assert result == {"api.key": "secret123", "timeout": "30"}
        assert mock_client.set_secret.call_count == 2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_delete_properties_success(self, mock_client_class, mock_credential, mock_env_vars):
        """Test successful property deletion"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties with prefix
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--key1"
        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--key2"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]

        # Mock deletion
        mock_poller = Mock()
        mock_poller.wait = Mock()
        mock_client.begin_delete_secret.return_value = mock_poller

        service = KeyVaultService()
        result = service.delete_properties("qa", "test-app")

        assert result == 2
        assert mock_client.begin_delete_secret.call_count == 2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_delete_properties_filters_by_prefix(
        self, mock_client_class, mock_credential, mock_env_vars
    ):
        """Test that delete_properties only deletes secrets matching the prefix"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock multiple secrets with different prefixes
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--key1"

        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--other-app--key2"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]

        # Mock deletion
        mock_poller = Mock()
        mock_poller.wait = Mock()
        mock_client.begin_delete_secret.return_value = mock_poller

        service = KeyVaultService()
        result = service.delete_properties("qa", "test-app")

        # Should only delete 1 (matching qa--test-app prefix)
        assert result == 1
        mock_client.begin_delete_secret.assert_called_once_with("qa--test-app--key1")

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_delete_properties_handles_not_found(
        self, mock_client_class, mock_credential, mock_env_vars
    ):
        """Test delete_properties handles ResourceNotFoundError gracefully"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        secret_prop = Mock(spec=SecretProperties)
        secret_prop.name = "qa--test-app--key1"
        mock_client.list_properties_of_secrets.return_value = [secret_prop]

        # Mock deletion raising ResourceNotFoundError
        mock_client.begin_delete_secret.side_effect = ResourceNotFoundError("Not found")

        service = KeyVaultService()
        result = service.delete_properties("qa", "test-app")

        # Should succeed despite the error
        assert result == 0

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_cache_hit_on_repeated_get(self, mock_client_class, mock_credential, mock_env_vars):
        """Test that cache is used on repeated get_properties calls"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties
        secret_prop = Mock(spec=SecretProperties)
        secret_prop.name = "qa--test-app--key1"
        mock_client.list_properties_of_secrets.return_value = [secret_prop]

        # Mock get_secret response
        mock_secret = Mock()
        mock_secret.value = "value1"
        mock_client.get_secret.return_value = mock_secret

        service = KeyVaultService()

        # First call - should hit Key Vault
        result1 = service.get_properties("qa", "test-app")
        assert result1 == {"key1": "value1"}
        assert mock_client.list_properties_of_secrets.call_count == 1

        # Second call - should hit cache
        result2 = service.get_properties("qa", "test-app")
        assert result2 == {"key1": "value1"}
        assert mock_client.list_properties_of_secrets.call_count == 1  # Not called again

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_cache_invalidation_on_set(self, mock_client_class, mock_credential, mock_env_vars):
        """Test that cache is invalidated when properties are set"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock for initial get
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--key1"

        mock_secret1 = Mock()
        mock_secret1.value = "value1"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1]
        mock_client.get_secret.return_value = mock_secret1

        service = KeyVaultService()

        # First get - populates cache
        result1 = service.get_properties("qa", "test-app")
        assert result1 == {"key1": "value1"}

        # Set properties - should invalidate cache
        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--key2"

        mock_secret2 = Mock()
        mock_secret2.value = "value2"

        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]
        mock_client.get_secret.side_effect = [mock_secret1, mock_secret2]

        result2 = service.set_properties("qa", "test-app", {"key2": "value2"})

        # Should see both keys now
        assert "key1" in result2
        assert "key2" in result2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_cache_invalidation_on_delete(self, mock_client_class, mock_credential, mock_env_vars):
        """Test that cache is invalidated when properties are deleted"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock for initial get
        secret_prop = Mock(spec=SecretProperties)
        secret_prop.name = "qa--test-app--key1"

        mock_secret = Mock()
        mock_secret.value = "value1"

        mock_client.list_properties_of_secrets.return_value = [secret_prop]
        mock_client.get_secret.return_value = mock_secret

        service = KeyVaultService()

        # First get - populates cache
        result1 = service.get_properties("qa", "test-app")
        assert result1 == {"key1": "value1"}

        # Delete properties
        mock_poller = Mock()
        mock_poller.wait = Mock()
        mock_client.begin_delete_secret.return_value = mock_poller

        service.delete_properties("qa", "test-app")

        # Next get should not use cache
        mock_client.list_properties_of_secrets.return_value = []
        result2 = service.get_properties("qa", "test-app")
        assert result2 == {}

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_cache_expiry(self, mock_client_class, mock_credential, mock_env_vars):
        """Test that cache expires after TTL"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Use very short TTL for testing (0.001 minutes ~ 60ms)
        service = KeyVaultService(cache_ttl_minutes=0.001)

        # Mock secret properties
        secret_prop = Mock(spec=SecretProperties)
        secret_prop.name = "qa--test-app--key1"
        mock_client.list_properties_of_secrets.return_value = [secret_prop]

        mock_secret = Mock()
        mock_secret.value = "value1"
        mock_client.get_secret.return_value = mock_secret

        # First call - should hit Key Vault
        result1 = service.get_properties("qa", "test-app")
        assert result1 == {"key1": "value1"}
        assert mock_client.list_properties_of_secrets.call_count == 1

        # Immediate second call - should hit cache
        result2 = service.get_properties("qa", "test-app")
        assert result2 == {"key1": "value1"}
        assert mock_client.list_properties_of_secrets.call_count == 1

        # Wait for cache to expire
        time.sleep(0.1)  # 100ms to ensure expiry

        # Third call - cache should be expired, hit Key Vault again
        result3 = service.get_properties("qa", "test-app")
        assert result3 == {"key1": "value1"}
        assert mock_client.list_properties_of_secrets.call_count == 2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_clear_cache(self, mock_client_class, mock_credential, mock_env_vars):
        """Test manual cache clearing"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties
        secret_prop = Mock(spec=SecretProperties)
        secret_prop.name = "qa--test-app--key1"
        mock_client.list_properties_of_secrets.return_value = [secret_prop]

        mock_secret = Mock()
        mock_secret.value = "value1"
        mock_client.get_secret.return_value = mock_secret

        service = KeyVaultService()

        # Populate cache
        service.get_properties("qa", "test-app")
        assert mock_client.list_properties_of_secrets.call_count == 1

        # Clear cache
        service.clear_cache()

        # Next call should hit Key Vault again
        service.get_properties("qa", "test-app")
        assert mock_client.list_properties_of_secrets.call_count == 2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_cache_isolation_between_apps(self, mock_client_class, mock_credential, mock_env_vars):
        """Test that different env/app combinations have separate cache entries"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        service = KeyVaultService()

        # Setup mocks for app1
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--app1--key1"
        mock_secret1 = Mock()
        mock_secret1.value = "value1"

        # Setup mocks for app2
        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--app2--key2"
        mock_secret2 = Mock()
        mock_secret2.value = "value2"

        # First call for app1
        mock_client.list_properties_of_secrets.return_value = [secret_prop1]
        mock_client.get_secret.return_value = mock_secret1
        result1 = service.get_properties("qa", "app1")
        assert result1 == {"key1": "value1"}

        # First call for app2 - should not use app1's cache
        mock_client.list_properties_of_secrets.return_value = [secret_prop2]
        mock_client.get_secret.return_value = mock_secret2
        result2 = service.get_properties("qa", "app2")
        assert result2 == {"key2": "value2"}

        # Both should have been called
        assert mock_client.list_properties_of_secrets.call_count == 2
