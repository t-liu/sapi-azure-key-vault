import os
import json
import logging
import secrets
import uuid
import azure.functions as func
from typing import Tuple
from pydantic import ValidationError

logger = logging.getLogger(__name__)
app = func.FunctionApp()

# Test each import individually
try:
    from app.constants import Config, ErrorMessages

    logger.info("✅ Constants imported")
except Exception as e:
    logger.error(f"❌ Constants import failed: {e}")

try:
    from app.models import PropertiesRequest

    logger.info("✅ Models imported")
except Exception as e:
    logger.error(f"❌ Models import failed: {e}")

try:
    from app.keyvault_service import KeyVaultService

    logger.info("✅ KeyVaultService imported")
except Exception as e:
    logger.error(f"❌ KeyVaultService import failed: {e}")

try:
    from app.rate_limiter import RateLimiter

    logger.info("✅ RateLimiter imported")
except Exception as e:
    logger.error(f"❌ RateLimiter import failed: {e}")


@app.function_name(name="test_imports")
@app.route(route="test-imports", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def test_imports(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse("Import test executed, check logs", status_code=200)
