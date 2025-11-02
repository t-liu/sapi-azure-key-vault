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
        """Test secret name generation with base64url encoding"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            name = service._generate_secret_name("qa", "test-app", "api.key")
            # "api.key" base64url encoded (without padding) is "YXBpLmtleQ"
            assert name == "qa--test-app--YXBpLmtleQ"

    def test_generate_secret_name_replaces_special_chars(self, mock_env_vars):
        """Test that env and app_key special characters are replaced, property key is base64url encoded"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            name = service._generate_secret_name("qa_env", "test.app", "api_key")
            # "api_key" base64url encoded (without padding) is "YXBpX2tleQ"
            assert name == "qa-env--test-app--YXBpX2tleQ"

    def test_property_key_encoding_is_reversible(self, mock_env_vars):
        """Test that property key encoding/decoding is reversible"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            test_keys = [
                "api.key",
                "api_key",
                "db.password",
                "https.port",
                "special/chars@test#key",
                "unicode_测试_key",
            ]
            for original_key in test_keys:
                name = service._generate_secret_name("qa", "test-app", original_key)
                # Extract encoded key from the secret name
                encoded_key = name.split("--")[-1]
                # Decode it back
                decoded_key = service._decode_property_key(encoded_key)
                assert decoded_key == original_key, f"Failed for key: {original_key}"

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

    def test_generate_secret_name_checks_length(self, mock_env_vars):
        """Test that secret names exceeding 127 chars raise ValueError"""
        with (
            patch("app.keyvault_service.DefaultAzureCredential"),
            patch("app.keyvault_service.SecretClient"),
        ):
            service = KeyVaultService()
            # Create a very long property key that will exceed 127 chars
            long_key = "a" * 100
            with pytest.raises(ValueError, match="Secret name too long.*max 127"):
                service._generate_secret_name("qa", "test-app", long_key)

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_get_properties_success(self, mock_client_class, mock_credential, mock_env_vars):
        """Test successful property retrieval with base64url encoded keys"""
        # Setup
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties with base64url encoded property keys
        # "https.port" base64url encoded (without padding) is "aHR0cHMucG9ydA"
        secret_prop1 = Mock(spec=SecretProperties)
        secret_prop1.name = "qa--test-app--aHR0cHMucG9ydA"

        # "db.password" base64url encoded (without padding) is "ZGIucGFzc3dvcmQ"
        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--ZGIucGFzc3dvcmQ"

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

        # Assert - should decode back to original keys
        assert "https.port" in properties
        assert properties["https.port"] == "443"
        assert "db.password" in properties
        assert properties["db.password"] == "secret123"

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
        mock_client.list_properties_of_secrets.return_value = []

        service = KeyVaultService()
        properties_to_set = {"api.key": "secret123", "timeout": "30"}

        with patch.object(service, "get_properties", return_value=properties_to_set):
            result = service.set_properties("qa", "test-app", properties_to_set)

        assert result == properties_to_set
        assert mock_client.set_secret.call_count == 2

    @patch("app.keyvault_service.DefaultAzureCredential")
    @patch("app.keyvault_service.SecretClient")
    def test_delete_properties_success(self, mock_client_class, mock_credential, mock_env_vars):
        """Test successful property deletion"""
        mock_client = Mock(spec=SecretClient)
        mock_client_class.return_value = mock_client

        # Mock secret properties
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

        assert result is True
        assert mock_client.begin_delete_secret.call_count == 2

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
        assert result is True

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
        mock_client.list_properties_of_secrets.return_value = [secret_prop1]

        mock_secret1 = Mock()
        mock_secret1.value = "value1"
        mock_client.get_secret.return_value = mock_secret1

        service = KeyVaultService()

        # First get - populates cache
        result1 = service.get_properties("qa", "test-app")
        assert result1 == {"key1": "value1"}

        # Set properties - should invalidate cache
        secret_prop2 = Mock(spec=SecretProperties)
        secret_prop2.name = "qa--test-app--key2"
        mock_client.list_properties_of_secrets.return_value = [secret_prop1, secret_prop2]

        mock_secret2 = Mock()
        mock_secret2.value = "value2"
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
        mock_client.list_properties_of_secrets.return_value = [secret_prop]

        mock_secret = Mock()
        mock_secret.value = "value1"
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

        # Use very short TTL for testing (0.1 seconds = 6 milliseconds)
        service = KeyVaultService(cache_ttl_minutes=0.001)  # ~60ms

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
