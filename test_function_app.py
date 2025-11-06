import azure.functions as func
import logging

logger = logging.getLogger(__name__)
app = func.FunctionApp()


@app.function_name(name="test_hello")
@app.route(route="hello", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def test_hello(req: func.HttpRequest) -> func.HttpResponse:
    logger.info("Test function executed")
    return func.HttpResponse("Hello! Functions are working!", status_code=200)
