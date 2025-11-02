#!/usr/bin/env python3
"""
Health check script for monitoring deployment
Can be run standalone or as part of CI/CD pipeline
"""
import os
import sys
import time
import argparse
import requests
from typing import Tuple


API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:7071")
API_CLIENT_ID = os.getenv("API_CLIENT_ID", "test-client-id")
API_CLIENT_SECRET = os.getenv("API_CLIENT_SECRET", "test-client-secret")


def check_api_health() -> Tuple[bool, str]:
    """
    Perform health check on the API

    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        headers = {"client_id": API_CLIENT_ID, "client_secret": API_CLIENT_SECRET}

        # Simple GET request to verify API is responding
        response = requests.get(
            f"{API_BASE_URL}/api/v1/properties",
            headers=headers,
            params={"env": "health", "appKey": "check"},
            timeout=5,
        )

        # Accept 200 as success (even if no properties exist)
        if response.status_code == 200:
            return True, "✅ API is healthy"
        elif response.status_code == 401:
            return False, "❌ Authentication failed"
        elif response.status_code >= 500:
            return False, f"❌ Server error: {response.status_code}"
        else:
            # 400 errors are OK for health check (invalid params)
            return True, "✅ API is responding (with validation error)"

    except requests.exceptions.Timeout:
        return False, "❌ Request timeout - API is slow or unresponsive"
    except requests.exceptions.ConnectionError:
        return False, "❌ Connection failed - API may be down"
    except Exception as e:
        return False, f"❌ Unexpected error: {str(e)}"


def monitor_health(duration_seconds: int = 60, interval_seconds: int = 5) -> bool:
    """
    Monitor API health over a period of time

    Args:
        duration_seconds: Total monitoring duration
        interval_seconds: Check interval

    Returns:
        True if all checks passed, False otherwise
    """
    print(f"🔍 Monitoring API health for {duration_seconds} seconds...")
    print(f"   Endpoint: {API_BASE_URL}")
    print(f"   Interval: {interval_seconds}s\n")

    start_time = time.time()
    check_count = 0
    failed_checks = 0

    while time.time() - start_time < duration_seconds:
        check_count += 1
        is_healthy, message = check_api_health()

        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] Check #{check_count}: {message}")

        if not is_healthy:
            failed_checks += 1

        time.sleep(interval_seconds)

    # Summary
    print(f"\n📊 Health Check Summary:")
    print(f"   Total checks: {check_count}")
    print(f"   Failed checks: {failed_checks}")
    print(f"   Success rate: {((check_count - failed_checks) / check_count * 100):.1f}%")

    # Consider healthy if < 20% failure rate
    success_rate = (check_count - failed_checks) / check_count
    is_healthy = success_rate >= 0.8

    if is_healthy:
        print("\n✅ Overall health check: PASSED")
    else:
        print("\n❌ Overall health check: FAILED")

    return is_healthy


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="API Health Check")
    parser.add_argument("--monitor", action="store_true", help="Enable continuous monitoring mode")
    parser.add_argument(
        "--duration", type=int, default=60, help="Monitoring duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--interval", type=int, default=5, help="Check interval in seconds (default: 5)"
    )

    args = parser.parse_args()

    if args.monitor:
        # Continuous monitoring mode
        is_healthy = monitor_health(args.duration, args.interval)
        sys.exit(0 if is_healthy else 1)
    else:
        # Single check mode
        is_healthy, message = check_api_health()
        print(message)
        sys.exit(0 if is_healthy else 1)


if __name__ == "__main__":
    main()
