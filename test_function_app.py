"""
Azure Function App for Key Vault Properties Management
Production-grade API for interacting with Azure Key Vault
"""

import os
import json
import logging
import uuid
import azure.functions as func

from app.keyvault_service import KeyVaultService
from app.rate_limiter import RateLimiter
from app.models import (
    PropertiesRequest,
    PropertiesResponse,
    PropertyResponse,
    PropertySetResponse,
    PropertiesSetResponse,
    DeleteResponse,
    ErrorResponse,
)
from app.constants import Config, ErrorMessages, HTTPHeaders, LogMessages

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize Azure Function App
app = func.FunctionApp()

# Initialize services at module load (thread-safe, happens once)
# Python modules are singletons by design - this is cleaner than lazy initialization
try:
    kv_service = KeyVaultService()
    logger.info(LogMessages.SERVICE_INIT_SUCCESS)
except Exception as e:
    logger.error(LogMessages.SERVICE_INIT_FAILURE.format(error=e))
    kv_service = None  # Will fail fast on first request

# Initialize Rate Limiter (uses Config defaults)
rate_limiter = RateLimiter()


def get_or_generate_correlation_id(req: func.HttpRequest) -> str:
    """
    Get correlation ID from request header or generate a new one

    Args:
        req: HTTP request object

    Returns:
        Correlation ID string
    """
    correlation_id = req.headers.get(HTTPHeaders.CORRELATION_ID) or req.headers.get(
        HTTPHeaders.REQUEST_ID
    )
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
    return correlation_id


@app.function_name(name="health_check")
@app.route(route="v1/health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """
    Health check endpoint for monitoring and load balancers

    Returns 200 if healthy, 503 if unhealthy
    No authentication required - this is a public endpoint
    """
    from datetime import datetime, timezone

    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "version": Config.APP_VERSION,
        "checks": {},
    }

    try:
        # Check if KeyVaultService is initialized
        if kv_service is None:
            health_status["status"] = "unhealthy"
            health_status["checks"]["key_vault_service"] = "not_initialized"
            logger.error(LogMessages.HEALTH_SERVICE_NOT_INITIALIZED)

            return func.HttpResponse(
                body=json.dumps(health_status), status_code=503, mimetype="application/json"
            )

        # Lightweight check - verify we can list secrets (fetch only 1)
        # This doesn't fetch all secrets, just checks connectivity
        secret_iterator = kv_service.client.list_properties_of_secrets()
        # Force evaluation of first item (or empty iterator)
        next(iter(secret_iterator), None)

        health_status["checks"]["key_vault"] = "healthy"

        logger.info(LogMessages.HEALTH_CHECK_PASSED)

        return func.HttpResponse(
            body=json.dumps(health_status), status_code=200, mimetype="application/json"
        )

    except Exception as e:
        health_status["status"] = "unhealthy"
        health_status["checks"]["key_vault"] = "unhealthy"
        logger.error(LogMessages.HEALTH_CHECK_FAILED.format(error=str(e)))

        return func.HttpResponse(
            body=json.dumps(health_status), status_code=503, mimetype="application/json"
        )
