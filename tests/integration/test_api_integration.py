"""
Integration tests for API endpoints
Tests against a real deployed environment
"""

import os
import pytest
import requests
from typing import Dict


# Get configuration from environment
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:7071")
API_CLIENT_ID = os.getenv("API_CLIENT_ID", "test-client-id")
API_CLIENT_SECRET = os.getenv("API_CLIENT_SECRET", "test-client-secret")
ENVIRONMENT = os.getenv("ENVIRONMENT", "staging")


@pytest.fixture
def api_headers() -> Dict[str, str]:
    """Return authentication headers for API requests"""
    return {
        "client_id": API_CLIENT_ID,
        "client_secret": API_CLIENT_SECRET,
        "Content-Type": "application/json",
    }


@pytest.fixture
def test_env():
    """Return test environment name"""
    return f"test-{ENVIRONMENT}"


@pytest.fixture
def test_app_key():
    """Return test application key"""
    return "integration-test-app"


class TestAPIIntegration:
    """Integration tests for the full API lifecycle"""

    def test_post_and_get_properties(self, api_headers, test_env, test_app_key):
        """Test creating properties and then retrieving them"""
        # POST - Create properties
        post_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": test_app_key,
                    "properties": {"test.property1": "value1", "test.property2": "value2"},
                }
            ]
        }

        post_response = requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=post_data, timeout=30
        )

        assert post_response.status_code == 201, f"POST failed: {post_response.text}"
        post_body = post_response.json()
        assert "responses" in post_body
        assert len(post_body["responses"]) > 0
        # Validate POST response format
        assert post_body["responses"][0]["environment"] == test_env
        assert post_body["responses"][0]["key"] == test_app_key
        assert post_body["responses"][0]["code"] == 200
        assert post_body["responses"][0]["message"] == "Properties Posted Successfully"

        # GET - Retrieve the same properties
        get_response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": test_app_key},
            timeout=30,
        )

        assert get_response.status_code == 200, f"GET failed: {get_response.text}"
        get_body = get_response.json()
        assert "responses" in get_body
        assert get_body["responses"][0]["properties"]["test.property1"] == "value1"
        assert get_body["responses"][0]["properties"]["test.property2"] == "value2"

    def test_put_updates_properties(self, api_headers, test_env, test_app_key):
        """Test updating properties using PUT"""
        # Create initial properties
        initial_data = {
            "properties": [
                {
                    "environment": test_env,
                    "key": test_app_key,
                    "properties": {"initial.key": "initial.value"},
                }
            ]
        }

        requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=initial_data, timeout=30
        )

        # Update with PUT
        update_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": test_app_key,
                    "properties": {"updated.key": "updated.value"},
                }
            ]
        }

        put_response = requests.put(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=update_data, timeout=30
        )

        assert put_response.status_code == 200, f"PUT failed: {put_response.text}"
        put_body = put_response.json()
        assert "responses" in put_body
        # Validate PUT response format
        assert put_body["responses"][0]["environment"] == test_env
        assert put_body["responses"][0]["key"] == test_app_key
        assert put_body["responses"][0]["code"] == 200
        assert put_body["responses"][0]["message"] == "Properties Updated Successfully"

        # Verify update
        get_response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": test_app_key},
            timeout=30,
        )

        get_body = get_response.json()
        assert "updated.key" in get_body["responses"][0]["properties"]

    def test_delete_removes_properties(self, api_headers, test_env, test_app_key):
        """Test deleting properties"""
        # Create properties
        post_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": test_app_key,
                    "properties": {"to.delete": "value"},
                }
            ]
        }

        requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=post_data, timeout=30
        )

        # Delete
        delete_response = requests.delete(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": test_app_key},
            timeout=30,
        )

        assert delete_response.status_code == 200, f"DELETE failed: {delete_response.text}"

        # Verify deletion
        get_response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": test_app_key},
            timeout=30,
        )

        get_body = get_response.json()
        # Should return empty properties after deletion
        assert len(get_body["responses"][0]["properties"]) == 0


class TestAPIAuthentication:
    """Integration tests for authentication"""

    def test_missing_auth_headers_returns_401(self):
        """Test that missing authentication returns 401"""
        response = requests.get(
            f"{API_BASE_URL}/v1/properties", params={"env": "qa", "key": "test"}, timeout=30
        )

        assert response.status_code == 401

    def test_invalid_credentials_returns_401(self):
        """Test that invalid credentials return 401"""
        invalid_headers = {"client_id": "invalid", "client_secret": "invalid"}

        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=invalid_headers,
            params={"env": "qa", "key": "test"},
            timeout=30,
        )

        assert response.status_code == 401


class TestAPIValidation:
    """Integration tests for request validation"""

    def test_missing_query_params_returns_400(self, api_headers):
        """Test that missing query parameters return 400"""
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": "qa"},  # Missing key
            timeout=30,
        )

        assert response.status_code == 400

    def test_invalid_post_body_returns_400(self, api_headers):
        """Test that invalid POST body returns 400"""
        invalid_data = {"invalid_key": "value"}  # Missing 'properties' key

        response = requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=invalid_data, timeout=30
        )

        assert response.status_code == 400


class TestSecurePropertiesIntegration:
    """Integration tests for secure properties endpoints"""

    def test_secure_properties_full_lifecycle(self, api_headers, test_env):
        """Test creating, retrieving, updating, and deleting secure properties"""
        secure_key = "integration-test-secrets"

        # POST - Create secure properties
        post_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": secure_key,
                    "properties": {
                        "api.client.id": "test-client-123",
                        "api.client.secret": "test-secret-456",
                    },
                }
            ]
        }

        post_response = requests.post(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            json=post_data,
            timeout=30,
        )

        assert post_response.status_code == 201, f"POST failed: {post_response.text}"
        post_body = post_response.json()
        assert "responses" in post_body
        assert post_body["responses"][0]["environment"] == test_env
        assert post_body["responses"][0]["key"] == secure_key
        assert post_body["responses"][0]["code"] == 200
        assert post_body["responses"][0]["message"] == "Secure Properties Posted Successfully"

        # GET - Retrieve the secure properties
        get_response = requests.get(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            params={"env": test_env, "key": secure_key},
            timeout=30,
        )

        assert get_response.status_code == 200, f"GET failed: {get_response.text}"
        get_body = get_response.json()
        assert "responses" in get_body
        assert get_body["responses"][0]["properties"]["api.client.id"] == "test-client-123"
        assert get_body["responses"][0]["properties"]["api.client.secret"] == "test-secret-456"

        # PUT - Update the secure properties
        update_data = {
            "properties": [
                {
                    "environment": test_env,
                    "key": secure_key,
                    "properties": {
                        "api.client.id": "updated-client-789",
                        "api.client.secret": "updated-secret-012",
                    },
                }
            ]
        }

        put_response = requests.put(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            json=update_data,
            timeout=30,
        )

        assert put_response.status_code == 200, f"PUT failed: {put_response.text}"
        put_body = put_response.json()
        assert put_body["responses"][0]["message"] == "Secure Properties Updated Successfully"

        # Verify update
        get_response2 = requests.get(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            params={"env": test_env, "key": secure_key},
            timeout=30,
        )

        get_body2 = get_response2.json()
        assert get_body2["responses"][0]["properties"]["api.client.id"] == "updated-client-789"

        # DELETE - Remove secure properties
        delete_response = requests.delete(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            params={"env": test_env, "key": secure_key},
            timeout=30,
        )

        assert delete_response.status_code == 200, f"DELETE failed: {delete_response.text}"
        delete_body = delete_response.json()
        assert "Successfully deleted secure properties" in delete_body["message"]
        assert delete_body["deleted_count"] >= 2

    def test_secure_properties_can_be_shared(self, api_headers, test_env):
        """Test that secure properties can be referenced by multiple applications"""
        secure_key = "shared-crm-secrets"

        # Create shared secure properties
        secure_data = {
            "properties": [
                {
                    "environment": test_env,
                    "key": secure_key,
                    "properties": {
                        "crm.client.id": "shared-client-id",
                        "crm.client.secret": "shared-secret",
                    },
                }
            ]
        }

        post_secure = requests.post(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            json=secure_data,
            timeout=30,
        )

        assert post_secure.status_code == 201

        # Create two different apps that reference the same secure properties
        app1_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": "app1-integration-test",
                    "properties": {
                        "app.name": "Application 1",
                        "secure.properties": secure_key,  # Reference to shared secrets
                    },
                }
            ]
        }

        app2_data = {
            "properties": [
                {
                    "environment": test_env,
                    "keys": "app2-integration-test",
                    "properties": {
                        "app.name": "Application 2",
                        "secure.properties": secure_key,  # Same reference
                    },
                }
            ]
        }

        # Create both apps
        requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=app1_data, timeout=30
        )
        requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=app2_data, timeout=30
        )

        # Retrieve secure properties - both apps can reference the same secrets
        secure_get = requests.get(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            params={"env": test_env, "key": secure_key},
            timeout=30,
        )

        assert secure_get.status_code == 200
        secure_body = secure_get.json()
        assert secure_body["responses"][0]["properties"]["crm.client.id"] == "shared-client-id"

        # Cleanup
        requests.delete(
            f"{API_BASE_URL}/v1/properties/secure",
            headers=api_headers,
            params={"env": test_env, "key": secure_key},
            timeout=30,
        )
        requests.delete(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": "app1-integration-test"},
            timeout=30,
        )
        requests.delete(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": test_env, "key": "app2-integration-test"},
            timeout=30,
        )
