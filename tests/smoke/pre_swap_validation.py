#!/usr/bin/env python3
"""
Pre-swap validation script
Validates staging slot before swapping to production
"""
import os
import sys
import requests
from typing import List, Tuple


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:7071")
API_CLIENT_ID = os.getenv("API_CLIENT_ID", "test-client-id")
API_CLIENT_SECRET = os.getenv("API_CLIENT_SECRET", "test-client-secret")


def validate_endpoint_get() -> Tuple[bool, str]:
    """Validate GET endpoint"""
    try:
        headers = {"client_id": API_CLIENT_ID, "client_secret": API_CLIENT_SECRET}

        response = requests.get(
            f"{API_BASE_URL}/api/v1/properties",
            headers=headers,
            params={"env": "validation", "key": "test"},
            timeout=5,
        )

        if response.status_code == 200:
            body = response.json()
            if "responses" in body:
                return True, "✅ GET endpoint validated"
            return False, "❌ GET response missing 'responses' key"

        return False, f"❌ GET endpoint returned {response.status_code}"

    except Exception as e:
        return False, f"❌ GET endpoint failed: {str(e)}"


def validate_endpoint_post() -> Tuple[bool, str]:
    """Validate POST endpoint"""
    try:
        headers = {
            "client_id": API_CLIENT_ID,
            "client_secret": API_CLIENT_SECRET,
            "Content-Type": "application/json",
        }

        data = {
            "properties": [
                {
                    "environment": "validation",
                    "key": "preswap-test",
                    "properties": {"validation": "test"},
                }
            ]
        }

        response = requests.post(
            f"{API_BASE_URL}/api/v1/properties", headers=headers, json=data, timeout=5
        )

        if response.status_code in [200, 201]:
            return True, "✅ POST endpoint validated"

        return False, f"❌ POST endpoint returned {response.status_code}"

    except Exception as e:
        return False, f"❌ POST endpoint failed: {str(e)}"


def validate_authentication() -> Tuple[bool, str]:
    """Validate authentication is working"""
    try:
        # Test with invalid credentials
        invalid_headers = {"client_id": "invalid", "client_secret": "invalid"}

        response = requests.get(
            f"{API_BASE_URL}/api/v1/properties",
            headers=invalid_headers,
            params={"env": "test", "key": "test"},
            timeout=5,
        )

        if response.status_code == 401:
            return True, "✅ Authentication validated"

        return False, f"❌ Expected 401, got {response.status_code}"

    except Exception as e:
        return False, f"❌ Authentication test failed: {str(e)}"


def validate_error_handling() -> Tuple[bool, str]:
    """Validate error handling"""
    try:
        headers = {
            "client_id": API_CLIENT_ID,
            "client_secret": API_CLIENT_SECRET,
            "Content-Type": "application/json",
        }

        # Send invalid data (missing top-level 'properties' key)
        invalid_data = {"invalid": "data"}

        response = requests.post(
            f"{API_BASE_URL}/api/v1/properties", headers=headers, json=invalid_data, timeout=5
        )

        if response.status_code == 400:
            body = response.json()
            if "error" in body or "message" in body:
                return True, "✅ Error handling validated"

        return False, f"❌ Expected 400 with error message, got {response.status_code}"

    except Exception as e:
        return False, f"❌ Error handling test failed: {str(e)}"


def run_validations() -> bool:
    """
    Run all pre-swap validations

    Returns:
        True if all validations pass, False otherwise
    """
    print("🔍 Running Pre-Swap Validations...")
    print(f"   Target: {API_BASE_URL}\n")

    validations = [
        ("GET Endpoint", validate_endpoint_get),
        ("POST Endpoint", validate_endpoint_post),
        ("Authentication", validate_authentication),
        ("Error Handling", validate_error_handling),
    ]

    results: List[Tuple[str, bool, str]] = []

    for name, validation_func in validations:
        is_valid, message = validation_func()
        results.append((name, is_valid, message))
        print(f"{name}: {message}")

    # Summary
    passed = sum(1 for _, is_valid, _ in results if is_valid)
    total = len(results)

    print(f"\n📊 Validation Summary: {passed}/{total} passed")

    all_passed = passed == total

    if all_passed:
        print("\n✅ ALL VALIDATIONS PASSED - Safe to swap slots")
    else:
        print("\n❌ VALIDATIONS FAILED - DO NOT swap slots")
        print("\nFailed validations:")
        for name, is_valid, message in results:
            if not is_valid:
                print(f"  - {name}: {message}")

    return all_passed


def main():
    """Main entry point"""
    try:
        all_passed = run_validations()
        sys.exit(0 if all_passed else 1)
    except Exception as e:
        print(f"\n❌ Fatal error during validation: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
