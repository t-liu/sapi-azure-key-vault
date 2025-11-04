"""
Unit tests for Azure Function HTTP triggers
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import azure.functions as func
from function_app import (
    validate_auth_headers,
    validate_query_params,
    create_error_response,
    get_properties,
    post_properties,
    put_properties,
    delete_properties,
    get_secure_properties,
    post_secure_properties,
    put_secure_properties,
    delete_secure_properties,
    health_check,
    rate_limiter,
)


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for authentication"""
    monkeypatch.setenv("VALID_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("VALID_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("AZURE_KEY_VAULT_URL", "https://test-vault.vault.azure.net/")


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter before each test"""
    rate_limiter.clear_all()
    yield
    rate_limiter.clear_all()


class TestValidateAuthHeaders:
    """Test authentication validation"""

    def test_valid_auth_headers(self, mock_env_vars):
        """Test with valid authentication headers"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {"client_id": "test-client-id", "client_secret": "test-client-secret"}

        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is True
        assert error_msg == ""

    def test_missing_client_id(self, mock_env_vars):
        """Test with missing client_id header"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {"client_secret": "test-client-secret"}

        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is False
        assert "Missing required headers" in error_msg

    def test_missing_client_secret(self, mock_env_vars):
        """Test with missing client_secret header"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {"client_id": "test-client-id"}

        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is False
        assert "Missing required headers" in error_msg

    def test_invalid_credentials(self, mock_env_vars):
        """Test with invalid credentials"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "wrong-id",
            "client_secret": "wrong-secret",
            "X-Forwarded-For": "1.2.3.4",
        }

        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is False
        assert "Invalid credentials" in error_msg

    def test_rate_limiting_enforced(self, mock_env_vars):
        """Test that rate limiting is enforced"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }

        # First request should succeed
        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is True

        # Exhaust rate limit
        for _ in range(99):  # Already made 1 request
            validate_auth_headers(req)

        # Next request should be rate limited
        is_valid, error_msg = validate_auth_headers(req)
        assert is_valid is False
        assert "Rate limit exceeded" in error_msg


class TestValidateQueryParams:
    """Test query parameter validation"""

    def test_valid_query_params(self):
        """Test with valid query parameters"""
        req = Mock(spec=func.HttpRequest)
        req.params = {"env": "qa", "key": "test-app"}

        env, app_key, error_msg = validate_query_params(req)
        assert env == "qa"
        assert app_key == "test-app"
        assert error_msg is None

    def test_missing_env_param(self):
        """Test with missing env parameter"""
        req = Mock(spec=func.HttpRequest)
        req.params = {"key": "test-app"}

        env, app_key, error_msg = validate_query_params(req)
        assert env is None
        assert app_key is None
        assert "Missing required query parameter: env" in error_msg

    def test_missing_key_param(self):
        """Test with missing key parameter"""
        req = Mock(spec=func.HttpRequest)
        req.params = {"env": "qa"}

        env, app_key, error_msg = validate_query_params(req)
        assert env is None
        assert app_key is None
        assert "Missing required query parameter: key" in error_msg


class TestCreateErrorResponse:
    """Test error response creation"""

    def test_create_error_response(self):
        """Test creating an error response"""
        response = create_error_response("ValidationError", "Test error", 400)

        assert response.status_code == 400
        assert response.mimetype == "application/json"

        body = json.loads(response.get_body())
        assert body["error"] == "ValidationError"
        assert body["message"] == "Test error"
        assert body["status_code"] == 400


class TestGetPropertiesEndpoint:
    """Test GET /v1/properties endpoint"""

    @patch("function_app.kv_service")
    def test_get_properties_success(self, mock_service, mock_env_vars):
        """Test successful GET request"""
        # Setup mock service
        mock_service.get_properties.return_value = {"https.port": "443"}

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.params = {"env": "qa", "key": "test-app"}

        # Execute
        response = get_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "responses" in body
        assert body["responses"][0]["env"] == "qa"
        assert body["responses"][0]["key"] == "test-app"

    @patch("function_app.kv_service")
    def test_get_properties_internal_error_masked(self, mock_service, mock_env_vars):
        """Test that internal errors don't expose details"""
        # Setup mock service to raise exception
        mock_service.get_properties.side_effect = Exception(
            "Internal database connection failed at /secret/path"
        )

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.params = {"env": "qa", "key": "test-app"}

        # Execute
        response = get_properties(req)

        # Assert
        assert response.status_code == 500
        body = json.loads(response.get_body())
        # Should NOT contain internal error details
        assert "database connection" not in body["message"]
        assert "/secret/path" not in body["message"]
        # Should contain generic message
        assert "unexpected error occurred" in body["message"].lower()

    def test_get_properties_invalid_auth(self, mock_env_vars):
        """Test GET request with invalid authentication"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {"client_id": "wrong", "client_secret": "wrong", "X-Forwarded-For": "1.2.3.4"}
        req.params = {"env": "qa", "key": "test-app"}

        response = get_properties(req)

        assert response.status_code == 401

    def test_get_properties_missing_params(self, mock_env_vars):
        """Test GET request with missing parameters"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {"client_id": "test-client-id", "client_secret": "test-client-secret"}
        req.params = {"env": "qa"}  # Missing key

        response = get_properties(req)

        assert response.status_code == 400


class TestPostPropertiesEndpoint:
    """Test POST /v1/properties endpoint"""

    @patch("function_app.kv_service")
    def test_post_properties_success(self, mock_service, mock_env_vars):
        """Test successful POST request"""
        # Setup mock service
        mock_service.set_properties.return_value = {"new-key": "new-value"}

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {"environment": "qa", "key": "test-app", "properties": {"new-key": "new-value"}}
            ]
        }

        # Execute
        response = post_properties(req)

        # Assert
        assert response.status_code == 201
        body = json.loads(response.get_body())
        assert "responses" in body
        assert len(body["responses"]) == 1
        assert body["responses"][0]["environment"] == "qa"
        assert body["responses"][0]["key"] == "test-app"
        assert body["responses"][0]["code"] == 200
        assert body["responses"][0]["message"] == "Properties Posted Successfully"

    def test_post_properties_missing_top_level_key(self, mock_env_vars):
        """Test POST request without 'properties' top-level key"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {"invalid_key": []}

        response = post_properties(req)

        assert response.status_code == 400
        body = json.loads(response.get_body())
        assert "properties" in body["message"].lower()

    def test_post_properties_invalid_data(self, mock_env_vars):
        """Test POST request with invalid data"""
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "",  # Invalid: empty environment
                    "key": "test-app",
                    "properties": {"key": "value"},
                }
            ]
        }

        response = post_properties(req)

        assert response.status_code == 400


class TestPutPropertiesEndpoint:
    """Test PUT /v1/properties endpoint"""

    @patch("function_app.kv_service")
    def test_put_properties_success(self, mock_service, mock_env_vars):
        """Test successful PUT request"""
        # Setup mock service
        mock_service.set_properties.return_value = {"updated-key": "updated-value"}

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "qa",
                    "key": "test-app",
                    "properties": {"updated-key": "updated-value"},
                }
            ]
        }

        # Execute
        response = put_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "responses" in body
        assert len(body["responses"]) == 1
        assert body["responses"][0]["environment"] == "qa"
        assert body["responses"][0]["key"] == "test-app"
        assert body["responses"][0]["code"] == 200
        assert body["responses"][0]["message"] == "Properties Updated Successfully"


class TestDeletePropertiesEndpoint:
    """Test DELETE /v1/properties endpoint"""

    @patch("function_app.kv_service")
    def test_delete_properties_success(self, mock_service, mock_env_vars):
        """Test successful DELETE request"""
        # Setup mock service
        mock_service.delete_properties.return_value = True

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.params = {"env": "qa", "key": "test-app"}

        # Execute
        response = delete_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "Successfully deleted" in body["message"]


class TestSecurePropertiesEndpoints:
    """Test secure properties endpoints"""

    @patch("function_app.kv_service")
    def test_get_secure_properties_success(self, mock_service, mock_env_vars):
        """Test successful GET secure properties request"""
        # Setup mock service
        mock_service.get_properties.return_value = {
            "crm.client.id": "test-id",
            "crm.client.secret": "test-secret",
        }

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.params = {"env": "qa", "key": "crm-secrets"}

        # Execute
        response = get_secure_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "responses" in body
        assert body["responses"][0]["env"] == "qa"
        assert body["responses"][0]["key"] == "crm-secrets"
        assert "crm.client.id" in body["responses"][0]["properties"]

    @patch("function_app.kv_service")
    def test_post_secure_properties_success(self, mock_service, mock_env_vars):
        """Test successful POST secure properties request"""
        # Setup mock service
        mock_service.set_properties.return_value = {"crm.client.id": "test-id"}

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "qa",
                    "key": "crm-secrets",
                    "properties": {"crm.client.id": "test-id", "crm.client.secret": "test-secret"},
                }
            ]
        }

        # Execute
        response = post_secure_properties(req)

        # Assert
        assert response.status_code == 201
        body = json.loads(response.get_body())
        assert "responses" in body
        assert len(body["responses"]) == 1
        assert body["responses"][0]["environment"] == "qa"
        assert body["responses"][0]["key"] == "crm-secrets"
        assert body["responses"][0]["code"] == 200
        assert body["responses"][0]["message"] == "Secure Properties Posted Successfully"

    @patch("function_app.kv_service")
    def test_put_secure_properties_success(self, mock_service, mock_env_vars):
        """Test successful PUT secure properties request"""
        # Setup mock service
        mock_service.set_properties.return_value = {"crm.client.id": "updated-id"}

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "qa",
                    "key": "crm-secrets",
                    "properties": {
                        "crm.client.id": "updated-id",
                        "crm.client.secret": "updated-secret",
                    },
                }
            ]
        }

        # Execute
        response = put_secure_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "responses" in body
        assert len(body["responses"]) == 1
        assert body["responses"][0]["environment"] == "qa"
        assert body["responses"][0]["key"] == "crm-secrets"
        assert body["responses"][0]["code"] == 200
        assert body["responses"][0]["message"] == "Secure Properties Updated Successfully"

    @patch("function_app.kv_service")
    def test_delete_secure_properties_success(self, mock_service, mock_env_vars):
        """Test successful DELETE secure properties request"""
        # Setup mock service
        mock_service.delete_properties.return_value = 2

        # Create mock request
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.params = {"env": "qa", "key": "crm-secrets"}

        # Execute
        response = delete_secure_properties(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert "Successfully deleted secure properties" in body["message"]
        assert body["env"] == "qa"
        assert body["key"] == "crm-secrets"
        assert body["deleted_count"] == 2

    @patch("function_app.kv_service")
    def test_post_secure_properties_with_reserved_key_rejected(self, mock_service, mock_env_vars):
        """Test that secure properties with 'secure.properties' key are rejected"""
        # Create mock request with reserved key
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "qa",
                    "key": "crm-secrets",
                    "properties": {
                        "crm.client.id": "test-id",
                        "secure.properties": "other-secrets",  # Reserved key!
                    },
                }
            ]
        }

        # Execute
        response = post_secure_properties(req)

        # Assert
        assert response.status_code == 400
        body = json.loads(response.get_body())
        assert body["error"] == "ValidationError"
        assert "cannot contain 'secure.properties' key" in body["message"]
        # Verify set_properties was never called
        mock_service.set_properties.assert_not_called()

    @patch("function_app.kv_service")
    def test_put_secure_properties_with_reserved_key_rejected(self, mock_service, mock_env_vars):
        """Test that secure properties with 'secure.properties' key are rejected on PUT"""
        # Create mock request with reserved key
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "prod",
                    "key": "app-secrets",
                    "properties": {
                        "api.key": "test-key",
                        "secure.properties": "crm-secrets",  # Reserved key!
                    },
                }
            ]
        }

        # Execute
        response = put_secure_properties(req)

        # Assert
        assert response.status_code == 400
        body = json.loads(response.get_body())
        assert body["error"] == "ValidationError"
        assert "cannot contain 'secure.properties' key" in body["message"]
        # Verify set_properties was never called
        mock_service.set_properties.assert_not_called()

    @patch("function_app.kv_service")
    def test_post_secure_properties_empty_rejected(self, mock_service, mock_env_vars):
        """Test that empty secure properties are rejected"""
        # Create mock request with empty properties
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "qa",
                    "key": "empty-secrets",
                    "properties": {},  # Empty!
                }
            ]
        }

        # Execute
        response = post_secure_properties(req)

        # Assert
        assert response.status_code == 400
        body = json.loads(response.get_body())
        assert body["error"] == "ValidationError"
        assert "cannot be empty" in body["message"]
        # Verify set_properties was never called
        mock_service.set_properties.assert_not_called()

    @patch("function_app.kv_service")
    def test_put_secure_properties_empty_rejected(self, mock_service, mock_env_vars):
        """Test that empty secure properties are rejected on PUT"""
        # Create mock request with empty properties
        req = Mock(spec=func.HttpRequest)
        req.headers = {
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "X-Forwarded-For": "1.2.3.4",
        }
        req.get_json.return_value = {
            "properties": [
                {
                    "environment": "prod",
                    "key": "empty-secrets",
                    "properties": {},  # Empty!
                }
            ]
        }

        # Execute
        response = put_secure_properties(req)

        # Assert
        assert response.status_code == 400
        body = json.loads(response.get_body())
        assert body["error"] == "ValidationError"
        assert "cannot be empty" in body["message"]
        # Verify set_properties was never called
        mock_service.set_properties.assert_not_called()


class TestHealthCheckEndpoint:
    """Test GET /api/v1/health endpoint"""

    @patch("function_app.kv_service")
    def test_health_check_healthy(self, mock_service):
        """Test health check when service is healthy"""
        # Setup mock service
        mock_iterator = iter([Mock()])  # Mock with one secret property
        mock_service.client.list_properties_of_secrets.return_value = mock_iterator

        # Create mock request (no auth required for health check)
        req = Mock(spec=func.HttpRequest)

        # Execute
        response = health_check(req)

        # Assert
        assert response.status_code == 200
        body = json.loads(response.get_body())
        assert body["status"] == "healthy"
        assert body["version"] == "2.0.0"
        assert body["checks"]["key_vault"] == "healthy"

    @patch("function_app.kv_service")
    def test_health_check_unhealthy(self, mock_service):
        """Test health check when Key Vault is unhealthy"""
        # Setup mock to raise exception
        mock_service.client.list_properties_of_secrets.side_effect = Exception("Connection error")

        # Create mock request
        req = Mock(spec=func.HttpRequest)

        # Execute
        response = health_check(req)

        # Assert
        assert response.status_code == 503
        body = json.loads(response.get_body())
        assert body["status"] == "unhealthy"
        assert body["checks"]["key_vault"] == "unhealthy"

    @patch("function_app.kv_service", None)
    def test_health_check_service_not_initialized(self):
        """Test health check when KeyVaultService is not initialized"""
        # Create mock request
        req = Mock(spec=func.HttpRequest)

        # Execute
        response = health_check(req)

        # Assert
        assert response.status_code == 503
        body = json.loads(response.get_body())
        assert body["status"] == "unhealthy"
        assert body["checks"]["key_vault_service"] == "not_initialized"
