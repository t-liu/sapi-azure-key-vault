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


@app.function_name(name="test_imports")
@app.route(route="test-imports", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def test_imports(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("Import test executed, check logs", status_code=200)
