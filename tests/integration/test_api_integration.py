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
                    "key": test_app_key,
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
                    "key": test_app_key,
                    "properties": {"updated.key": "updated.value"},
                }
            ]
        }

        put_response = requests.put(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=update_data, timeout=30
        )

        assert put_response.status_code == 200, f"PUT failed: {put_response.text}"

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
                {"environment": test_env, "key": test_app_key, "properties": {"to.delete": "value"}}
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
