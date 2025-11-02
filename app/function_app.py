"""
Azure Function App for Key Vault Properties Management
Production-grade API for interacting with Azure Key Vault
"""

import os
import json
import logging
import secrets
import uuid
import azure.functions as func
from typing import Tuple
from pydantic import ValidationError

from app.keyvault_service import KeyVaultService
from app.rate_limiter import RateLimiter
from app.models import (
    PropertiesRequest,
    PropertiesResponse,
    PropertyResponse,
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


@app.route(route="api/v1/health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """
    Health check endpoint for monitoring and load balancers

    Returns 200 if healthy, 503 if unhealthy
    No authentication required - this is a public endpoint
    """
    from datetime import datetime

    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
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


def validate_auth_headers(req: func.HttpRequest) -> Tuple[bool, str]:
    """
    Validate client_id and client_secret headers with timing-attack protection

    Args:
        req: HTTP request object

    Returns:
        Tuple of (is_valid, error_message)
    """
    client_id = req.headers.get(HTTPHeaders.CLIENT_ID, "")
    client_secret = req.headers.get(HTTPHeaders.CLIENT_SECRET, "")

    # Extract client IP early for logging purposes across all code paths
    client_ip = req.headers.get(
        HTTPHeaders.FORWARDED_FOR, req.headers.get(HTTPHeaders.REAL_IP, "unknown")
    )

    if not client_id or not client_secret:
        return False, ErrorMessages.AUTH_MISSING_HEADERS

    # Validate against environment variables
    valid_client_id = os.getenv("VALID_CLIENT_ID", "")
    valid_client_secret = os.getenv("VALID_CLIENT_SECRET", "")

    if not valid_client_id or not valid_client_secret:
        logger.error("VALID_CLIENT_ID or VALID_CLIENT_SECRET not configured")
        return False, ErrorMessages.AUTH_CONFIG_ERROR

    # Use constant-time comparison to prevent timing attacks
    id_match = secrets.compare_digest(client_id, valid_client_id)
    secret_match = secrets.compare_digest(client_secret, valid_client_secret)

    if not (id_match and secret_match):
        # Log IP address instead of client_id to avoid credential exposure
        logger.warning(LogMessages.AUTH_INVALID_ATTEMPT.format(ip=client_ip))
        return False, ErrorMessages.AUTH_INVALID_CREDENTIALS

    # Check rate limiting after successful auth validation
    if not rate_limiter.is_allowed(client_id):
        logger.warning(LogMessages.AUTH_RATE_LIMIT_EXCEEDED.format(ip=client_ip))
        return False, ErrorMessages.AUTH_RATE_LIMITED

    return True, ""


def create_error_response(
    error_type: str, message: str, status_code: int = 400, correlation_id: str = ""
) -> func.HttpResponse:
    """
    Create a standardized error response with correlation ID

    Args:
        error_type: Type of error
        message: Error message
        status_code: HTTP status code
        correlation_id: Optional correlation ID to include in response headers

    Returns:
        HttpResponse with error details
    """
    error_response = ErrorResponse(error=error_type, message=message, status_code=status_code)

    headers = {HTTPHeaders.CONTENT_TYPE: HTTPHeaders.CONTENT_TYPE_JSON}
    if correlation_id:
        headers[HTTPHeaders.CORRELATION_ID] = correlation_id

    return func.HttpResponse(
        body=error_response.model_dump_json(),
        status_code=status_code,
        mimetype=HTTPHeaders.CONTENT_TYPE_JSON,
        headers=headers,
    )


def validate_query_params(req: func.HttpRequest) -> Tuple[str, str, str]:
    """
    Validate and extract env and key query parameters

    Args:
        req: HTTP request object

    Returns:
        Tuple of (env, app_key, error_message)
    """
    env = req.params.get("env")
    app_key = req.params.get("key")

    if not env:
        return None, None, ErrorMessages.VALIDATION_MISSING_ENV

    if not app_key:
        return None, None, ErrorMessages.VALIDATION_MISSING_APP_KEY

    return env, app_key, None


@app.route(route="api/v1/properties", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_properties(req: func.HttpRequest) -> func.HttpResponse:
    """
    GET endpoint to retrieve properties from Key Vault

    Query Parameters:
        env: Environment name (e.g., 'qa', 'prod')
        key: Application key identifier

    Headers:
        client_id: Client ID for authentication
        client_secret: Client secret for authentication
        X-Correlation-ID: Optional correlation ID for request tracking

    Returns:
        JSON response with properties and X-Correlation-ID header
    """
    # Generate or extract correlation ID
    correlation_id = get_or_generate_correlation_id(req)
    logger.info(f"[{correlation_id}] GET /api/v1/properties - Request received")

    # Validate authentication
    is_valid, error_msg = validate_auth_headers(req)
    if not is_valid:
        return create_error_response("AuthenticationError", error_msg, 401, correlation_id)

    # Validate query parameters
    env, app_key, error_msg = validate_query_params(req)
    if error_msg:
        return create_error_response("ValidationError", error_msg, 400, correlation_id)

    try:
        # Get properties from Key Vault
        properties = kv_service.get_properties(env, app_key)

        # Build response
        response = PropertiesResponse(
            responses=[PropertyResponse(env=env, key=app_key, properties=properties)]
        )

        logger.info(f"[{correlation_id}] GET /api/v1/properties - Success for {env}/{app_key}")
        return func.HttpResponse(
            body=response.model_dump_json(),
            status_code=200,
            mimetype=HTTPHeaders.CONTENT_TYPE_JSON,
            headers={HTTPHeaders.CORRELATION_ID: correlation_id},
        )

    except Exception as e:
        logger.error(f"[{correlation_id}] GET /api/v1/properties - Error: {str(e)}", exc_info=True)
        # Don't expose internal error details to clients
        return create_error_response(
            "InternalError", ErrorMessages.INTERNAL_ERROR, 500, correlation_id
        )


def _process_properties_request(req: func.HttpRequest, method: str) -> func.HttpResponse:
    """
    Shared logic for POST and PUT requests
    Both endpoints have identical functionality, differing only in status codes

    Args:
        req: HTTP request object
        method: HTTP method name ("POST" or "PUT") for logging and status codes

    Returns:
        HTTP response with processed properties and X-Correlation-ID header
    """
    # Generate or extract correlation ID
    correlation_id = get_or_generate_correlation_id(req)
    logger.info(f"[{correlation_id}] {method} /api/v1/properties - Request received")

    # Validate authentication
    is_valid, error_msg = validate_auth_headers(req)
    if not is_valid:
        return create_error_response("AuthenticationError", error_msg, 401, correlation_id)

    try:
        # Parse and validate request body
        body = req.get_json()

        # Check if top-level key is "properties"
        if not body or "properties" not in body:
            return create_error_response(
                "ValidationError",
                ErrorMessages.VALIDATION_MISSING_PROPERTIES_KEY,
                400,
                correlation_id,
            )

        # Validate with Pydantic model
        request_data = PropertiesRequest(**body)

        # Process each property item
        responses = []

        for item in request_data.properties:
            # Set properties in Key Vault
            updated_properties = kv_service.set_properties(
                item.environment, item.key, item.properties
            )

            # Add to responses
            responses.append(
                PropertyResponse(env=item.environment, key=item.key, properties=updated_properties)
            )

        # Build response
        response = PropertiesResponse(responses=responses)

        # Use 201 Created for POST, 200 OK for PUT
        status_code = 201 if method == "POST" else 200

        logger.info(
            f"[{correlation_id}] {method} /api/v1/properties - Success, processed {len(responses)} items"
        )
        return func.HttpResponse(
            body=response.model_dump_json(),
            status_code=status_code,
            mimetype=HTTPHeaders.CONTENT_TYPE_JSON,
            headers={HTTPHeaders.CORRELATION_ID: correlation_id},
        )

    except ValidationError as e:
        logger.warning(
            f"[{correlation_id}] {method} /api/v1/properties - Validation error: {str(e)}"
        )
        return create_error_response("ValidationError", str(e), 400, correlation_id)

    except ValueError as e:
        logger.warning(f"[{correlation_id}] {method} /api/v1/properties - Value error: {str(e)}")
        return create_error_response("ValidationError", str(e), 400, correlation_id)

    except Exception as e:
        logger.error(
            f"[{correlation_id}] {method} /api/v1/properties - Error: {str(e)}", exc_info=True
        )
        # Don't expose internal error details to clients
        return create_error_response(
            "InternalError", ErrorMessages.INTERNAL_ERROR, 500, correlation_id
        )


@app.route(route="api/v1/properties", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def post_properties(req: func.HttpRequest) -> func.HttpResponse:
    """
    POST endpoint to create/update properties in Key Vault

    Headers:
        client_id: Client ID for authentication
        client_secret: Client secret for authentication

    Request Body:
        {
            "properties": [
                {
                    "environment": "qa",
                    "key": "app-key",
                    "properties": {
                        "key1": "value1",
                        "key2": "value2"
                    }
                }
            ]
        }

    Returns:
        JSON response with updated properties (status 201)
    """
    return _process_properties_request(req, "POST")


@app.route(route="api/v1/properties", methods=["PUT"], auth_level=func.AuthLevel.ANONYMOUS)
def put_properties(req: func.HttpRequest) -> func.HttpResponse:
    """
    PUT endpoint to update properties in Key Vault

    Headers:
        client_id: Client ID for authentication
        client_secret: Client secret for authentication

    Request Body:
        {
            "properties": [
                {
                    "environment": "qa",
                    "key": "app-key",
                    "properties": {
                        "key1": "value1",
                        "key2": "value2"
                    }
                }
            ]
        }

    Returns:
        JSON response with updated properties (status 200)
    """
    return _process_properties_request(req, "PUT")


@app.route(route="api/v1/properties", methods=["DELETE"], auth_level=func.AuthLevel.ANONYMOUS)
def delete_properties(req: func.HttpRequest) -> func.HttpResponse:
    """
    DELETE endpoint to remove properties from Key Vault

    Query Parameters:
        env: Environment name (e.g., 'qa', 'prod')
        key: Application key identifier

    Headers:
        client_id: Client ID for authentication
        client_secret: Client secret for authentication
        X-Correlation-ID: Optional correlation ID for request tracking

    Returns:
        JSON response with deletion details and X-Correlation-ID header
    """
    # Generate or extract correlation ID
    correlation_id = get_or_generate_correlation_id(req)
    logger.info(f"[{correlation_id}] DELETE /api/v1/properties - Request received")

    # Validate authentication
    is_valid, error_msg = validate_auth_headers(req)
    if not is_valid:
        return create_error_response("AuthenticationError", error_msg, 401, correlation_id)

    # Validate query parameters
    env, app_key, error_msg = validate_query_params(req)
    if error_msg:
        return create_error_response("ValidationError", error_msg, 400, correlation_id)

    try:
        # Delete properties from Key Vault (returns count of deleted properties)
        deleted_count = kv_service.delete_properties(env, app_key)

        # Build response using Pydantic model
        response = DeleteResponse(
            message=f"Successfully deleted properties for {env}/{app_key}",
            env=env,
            key=app_key,
            deleted_count=deleted_count,
        )

        logger.info(
            f"[{correlation_id}] DELETE /api/v1/properties - Success for {env}/{app_key}, deleted {deleted_count} properties"
        )
        return func.HttpResponse(
            body=response.model_dump_json(),
            status_code=200,
            mimetype=HTTPHeaders.CONTENT_TYPE_JSON,
            headers={HTTPHeaders.CORRELATION_ID: correlation_id},
        )

    except Exception as e:
        logger.error(
            f"[{correlation_id}] DELETE /api/v1/properties - Error: {str(e)}", exc_info=True
        )
        # Don't expose internal error details to clients
        return create_error_response(
            "InternalError", ErrorMessages.INTERNAL_ERROR, 500, correlation_id
        )
