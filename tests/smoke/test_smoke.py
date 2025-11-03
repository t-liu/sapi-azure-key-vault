"""
Smoke tests for quick validation after deployment
Fast, critical path tests that verify basic functionality
"""

import os
import pytest
import requests


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:7071")
API_CLIENT_ID = os.getenv("API_CLIENT_ID", "test-client-id")
API_CLIENT_SECRET = os.getenv("API_CLIENT_SECRET", "test-client-secret")


@pytest.fixture
def api_headers():
    """Return authentication headers"""
    return {
        "client_id": API_CLIENT_ID,
        "client_secret": API_CLIENT_SECRET,
        "Content-Type": "application/json",
    }


@pytest.mark.smoke
class TestSmokeTests:
    """Critical smoke tests for deployment validation"""

    def test_api_is_reachable(self, api_headers):
        """Verify API endpoint is reachable"""
        try:
            response = requests.get(
                f"{API_BASE_URL}/v1/properties",
                headers=api_headers,
                params={"env": "smoke", "key": "test"},
                timeout=10,
            )
            # Should get either 200 or 400, but not 404 or 500
            assert response.status_code in [
                200,
                400,
                401,
            ], f"API unreachable or returning error: {response.status_code}"
        except requests.exceptions.ConnectionError:
            pytest.fail("Cannot connect to API - service may be down")

    def test_authentication_works(self, api_headers):
        """Verify authentication is working"""
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": "smoke", "key": "test"},
            timeout=10,
        )

        # Should not return 500 (server error)
        assert response.status_code != 500, "Server error detected"

        # Should authenticate successfully
        assert response.status_code != 401, "Authentication failed"

    def test_get_endpoint_responds(self, api_headers):
        """Verify GET endpoint is functional"""
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": "smoke", "key": "test"},
            timeout=10,
        )

        assert response.status_code == 200
        assert "responses" in response.json()

    def test_post_endpoint_responds(self, api_headers):
        """Verify POST endpoint is functional"""
        data = {
            "properties": [
                {"environment": "smoke", "key": "smoke-test", "properties": {"smoke": "test"}}
            ]
        }

        response = requests.post(
            f"{API_BASE_URL}/v1/properties", headers=api_headers, json=data, timeout=10
        )

        # Should create successfully or return validation error, but not 500
        assert response.status_code in [200, 201, 400]
        assert response.status_code != 500

    def test_response_format_is_valid(self, api_headers):
        """Verify API returns valid JSON in correct format"""
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": "smoke", "key": "test"},
            timeout=10,
        )

        assert response.headers.get("Content-Type") == "application/json"

        body = response.json()
        assert "responses" in body
        assert isinstance(body["responses"], list)

    def test_error_handling_works(self):
        """Verify error handling returns proper error responses"""
        # Request without authentication
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            params={"env": "smoke", "key": "test"},
            timeout=10,
        )

        assert response.status_code == 401
        body = response.json()
        assert "error" in body or "message" in body

    def test_response_time_acceptable(self, api_headers):
        """Verify API response time is acceptable (< 3 seconds)"""
        import time

        start_time = time.time()
        response = requests.get(
            f"{API_BASE_URL}/v1/properties",
            headers=api_headers,
            params={"env": "smoke", "key": "test"},
            timeout=10,
        )
        elapsed_time = time.time() - start_time

        assert response.status_code == 200
        assert elapsed_time < 3.0, f"Response time too slow: {elapsed_time:.2f}s"
