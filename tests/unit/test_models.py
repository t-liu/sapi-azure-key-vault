import pytest
from pydantic import ValidationError
from app.models import (
    PropertyItem,
    PropertiesRequest,
    PropertyResponse,
    PropertiesResponse,
    ErrorResponse,
)


class TestPropertyItem:
    """Test PropertyItem model validation"""

    def test_valid_property_item(self):
        """Test creating a valid PropertyItem"""
        item = PropertyItem(
            environment="qa", key="test-app", properties={"key1": "value1", "key2": "value2"}
        )
        # FIX: Use .dict() to access fields in Pydantic v1
        assert item.dict()["environment"] == "qa"
        assert item.dict()["key"] == "test-app"
        assert item.dict()["properties"] == {"key1": "value1", "key2": "value2"}

    def test_empty_environment_fails(self):
        """Test that empty environment raises validation error"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="", key="test-app", properties={"key1": "value1"})

    def test_empty_key_fails(self):
        """Test that empty key raises validation error"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="", properties={"key1": "value1"})

    def test_empty_properties_fails(self):
        """Test that empty properties dict raises validation error"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test-app", properties={})

    def test_whitespace_only_values_fail(self):
        """Test that whitespace-only values raise validation error"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="   ", key="test-app", properties={"key1": "value1"})

    def test_max_environment_length(self):
        """Test that environment exceeding 50 chars fails"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="a" * 51, key="test-app", properties={"key": "value"})

    def test_max_key_length(self):
        """Test that key exceeding 100 chars fails"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="a" * 101, properties={"key": "value"})

    def test_invalid_characters_in_environment(self):
        """Test that invalid characters in environment fail"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa@prod", key="test-app", properties={"key": "value"})

    def test_invalid_characters_in_key(self):
        """Test that invalid characters in key fail"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test/app", properties={"key": "value"})

    def test_valid_special_characters(self):
        """Test that hyphens, underscores, dots are allowed"""
        item = PropertyItem(
            environment="qa-env_1.0", key="test-app_v1.2", properties={"key": "value"}
        )
        # FIX: Use .dict() to access fields in Pydantic v1
        item_dict = item.dict()
        assert item_dict["environment"] == "qa-env_1.0"
        assert item_dict["key"] == "test-app_v1.2"

    def test_too_many_properties(self):
        """Test that more than 100 properties fails"""
        properties = {f"key{i}": f"value{i}" for i in range(101)}
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test-app", properties=properties)

    def test_property_key_too_long(self):
        """Test that property key exceeding 127 chars fails"""
        long_key = "a" * 128
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test-app", properties={long_key: "value"})

    def test_property_value_too_long(self):
        """Test that property value exceeding 25KB fails"""
        long_value = "a" * 25001
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test-app", properties={"key": long_value})

    def test_empty_property_value_fails(self):
        """Test that empty property value fails"""
        with pytest.raises(ValidationError):
            PropertyItem(environment="qa", key="test-app", properties={"key": ""})


class TestPropertiesRequest:
    """Test PropertiesRequest model validation"""

    def test_valid_properties_request(self):
        """Test creating a valid PropertiesRequest"""
        request = PropertiesRequest(
            properties=[PropertyItem(environment="qa", key="app1", properties={"key1": "value1"})]
        )
        # FIX: Use .dict() to access fields in Pydantic v1
        assert len(request.dict()["properties"]) == 1

    def test_empty_properties_list_fails(self):
        """Test that empty properties list raises validation error"""
        with pytest.raises(ValidationError):
            PropertiesRequest(properties=[])

    def test_multiple_property_items(self):
        """Test request with multiple property items"""
        request = PropertiesRequest(
            properties=[
                PropertyItem(environment="qa", key="app1", properties={"k1": "v1"}),
                PropertyItem(environment="prod", key="app2", properties={"k2": "v2"}),
            ]
        )
        # FIX: Use .dict() to access fields in Pydantic v1
        assert len(request.dict()["properties"]) == 2

    def test_too_many_items_in_batch_fails(self):
        """Test that more than 10 items in batch fails"""
        items = [
            PropertyItem(environment="qa", key=f"app{i}", properties={"k": "v"}) for i in range(11)
        ]
        with pytest.raises(ValidationError):
            PropertiesRequest(properties=items)


class TestPropertyResponse:
    """Test PropertyResponse model"""

    def test_valid_property_response(self):
        """Test creating a valid PropertyResponse"""
        response = PropertyResponse(env="qa", key="test-app", properties={"key1": "value1"})
        # FIX: Use .dict() to access fields in Pydantic v1
        response_dict = response.dict()
        assert response_dict["env"] == "qa"
        assert response_dict["key"] == "test-app"
        assert response_dict["properties"] == {"key1": "value1"}


class TestPropertiesResponse:
    """Test PropertiesResponse model"""

    def test_valid_properties_response(self):
        """Test creating a valid PropertiesResponse"""
        response = PropertiesResponse(
            responses=[PropertyResponse(env="qa", key="test-app", properties={"key1": "value1"})]
        )
        # FIX: Use .dict() to access fields in Pydantic v1
        assert len(response.dict()["responses"]) == 1

    def test_serialize_to_json(self):
        """Test serialization to JSON"""
        response = PropertiesResponse(
            responses=[PropertyResponse(env="qa", key="test-app", properties={"key1": "value1"})]
        )
        # FIX: Use .json() in Pydantic v1 (returns string)
        json_str = response.json()
        assert "qa" in json_str
        assert "test-app" in json_str


class TestErrorResponse:
    """Test ErrorResponse model"""

    def test_valid_error_response(self):
        """Test creating a valid ErrorResponse"""
        error = ErrorResponse(error="ValidationError", message="Invalid input", status_code=400)
        # FIX: Use .dict() to access fields in Pydantic v1
        error_dict = error.dict()
        assert error_dict["error"] == "ValidationError"
        assert error_dict["message"] == "Invalid input"
        assert error_dict["status_code"] == 400
