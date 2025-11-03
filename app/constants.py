"""
Constants for Azure Key Vault Properties API

Centralized configuration values and magic strings for maintainability
"""


class Config:
    """Application configuration constants"""

    # API Configuration
    APP_VERSION = "2.0.0"
    # Note: API routes are defined directly in function decorators (@app.route)
    # API_VERSION and API_BASE_PATH reserved for future version negotiation if needed

    # Key Vault Configuration
    SECRET_NAME_SEPARATOR = "--"
    MAX_SECRET_NAME_LENGTH = 127
    MAX_SECRET_VALUE_LENGTH = 25000  # 25KB

    # Rate Limiting Configuration
    RATE_LIMIT_MAX_REQUESTS = 100
    RATE_LIMIT_WINDOW_SECONDS = 60

    # Caching Configuration
    CACHE_TTL_MINUTES = 5

    # Validation Limits
    MAX_ENVIRONMENT_LENGTH = 50
    MAX_APP_KEY_LENGTH = 100
    MAX_PROPERTIES_PER_REQUEST = 100
    MAX_ITEMS_PER_BATCH = 10

    # Retry Configuration
    RETRY_MAX_ATTEMPTS = 3
    RETRY_MIN_WAIT_SECONDS = 2
    RETRY_MAX_WAIT_SECONDS = 10
    RETRY_MULTIPLIER = 1


class ErrorMessages:
    """Standard error messages"""

    # Authentication Errors
    AUTH_MISSING_HEADERS = "Missing required headers: client_id and client_secret"
    AUTH_INVALID_CREDENTIALS = "Invalid credentials"
    AUTH_CONFIG_ERROR = "Authentication configuration error"
    AUTH_RATE_LIMITED = "Rate limit exceeded. Please try again later."

    # Validation Errors
    VALIDATION_MISSING_ENV = "Missing required query parameter: env"
    VALIDATION_MISSING_APP_KEY = "Missing required query parameter: key"
    VALIDATION_MISSING_PROPERTIES_KEY = "Request body must contain top-level key 'properties'"

    # Internal Errors
    INTERNAL_ERROR = "An unexpected error occurred"

    # Reserved error messages for future enhanced error handling:
    # SERVICE_UNAVAILABLE - for specific Azure service unavailability
    # KEYVAULT_NOT_FOUND - for explicit "no properties found" vs empty results
    # KEYVAULT_ACCESS_DENIED - for specific permission errors
    # VALIDATION_INVALID_REQUEST_BODY - covered by Pydantic ValidationError


class LogMessages:
    """Standard log message templates"""

    # Service Initialization
    SERVICE_INIT_SUCCESS = "KeyVaultService initialized successfully at module load"
    SERVICE_INIT_FAILURE = "Failed to initialize KeyVaultService: {error}"

    # Authentication
    AUTH_INVALID_ATTEMPT = "Invalid authentication attempt from IP: {ip}"
    AUTH_RATE_LIMIT_EXCEEDED = "Rate limit exceeded from IP: {ip}"

    # Cache Operations
    CACHE_HIT = "Cache hit for {cache_key} (age: {age}s)"
    CACHE_MISS = "Cache miss for {cache_key}, fetching from Key Vault"
    CACHE_INVALIDATED = "Cache invalidated for {cache_key}"
    CACHE_CLEARED = "Cache cleared ({count} entries removed)"

    # Health Check
    HEALTH_CHECK_PASSED = "Health check passed"
    HEALTH_CHECK_FAILED = "Health check failed: {error}"
    HEALTH_SERVICE_NOT_INITIALIZED = "Health check failed: KeyVaultService not initialized"


class HTTPHeaders:
    """HTTP header names"""

    # Authentication
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"

    # Request Tracking
    CORRELATION_ID = "X-Correlation-ID"
    REQUEST_ID = "X-Request-ID"

    # Client Information
    FORWARDED_FOR = "X-Forwarded-For"
    REAL_IP = "X-Real-IP"

    # Content Type
    CONTENT_TYPE = "Content-Type"
    CONTENT_TYPE_JSON = "application/json"
