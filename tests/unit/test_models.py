import pytest
import json
from pydantic import ValidationError
from app.models import (
    PropertyItem,
    PropertiesRequest,
    PropertyResponse,
    PropertiesResponse,
    PropertySetResponse,
    PropertiesSetResponse,
    DeleteResponse,
    ErrorResponse,
)
from app.constants import Config


class TestPropertyItem:
    """Test PropertyItem model validation"""

    def test_valid_property_item(self):
        """Test creating a valid PropertyItem"""
        item = PropertyItem(
            environment="qa", keys="test-app", properties={"key1": "value1", "key2": "value2"}
        )
        assert item.environment == "qa"
        assert item.keys_ == "test-app"
        assert item.properties_ == {"key1": "value1", "key2": "value2"}

    def test_empty_environment_fails(self):
        """Test that empty environment raises validation error"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="", keys="test-app", properties={"key1": "value1"})
        assert "Environment cannot be empty" in str(exc_info.value)

    def test_empty_keys_fails(self):
        """Test that empty key raises validation error"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="", properties={"key1": "value1"})
        assert "Keys cannot be empty" in str(exc_info.value)

    def test_empty_properties_fails(self):
        """Test that empty properties dict raises validation error"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="test-app", properties={})
        assert "Properties dictionary cannot be empty" in str(exc_info.value)

    def test_whitespace_only_environment_fails(self):
        """Test that whitespace-only environment raises validation error"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="   ", keys="test-app", properties={"key1": "value1"})
        assert "Environment cannot be empty" in str(exc_info.value)

    def test_whitespace_only_key_fails(self):
        """Test that whitespace-only key raises validation error"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="   ", properties={"key1": "value1"})
        assert "Keys cannot be empty" in str(exc_info.value)

    def test_max_environment_length(self):
        """Test that environment exceeding max chars fails"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(
                environment="a" * (Config.MAX_ENVIRONMENT_LENGTH + 1),
                keys="test-app",
                properties={"key": "value"},
            )
        assert (
            f"cannot exceed {Config.MAX_ENVIRONMENT_LENGTH} characters"
            in str(exc_info.value).lower()
        )

    def test_max_key_length(self):
        """Test that key exceeding max chars fails"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(
                environment="qa",
                keys="a" * (Config.MAX_APP_KEY_LENGTH + 1),
                properties={"key": "value"},
            )
        assert (
            f"cannot exceed {Config.MAX_APP_KEY_LENGTH} characters" in str(exc_info.value).lower()
        )

    def test_invalid_characters_in_environment(self):
        """Test that invalid characters in environment fail"""
        invalid_chars = ["qa@prod", "qa#test", "qa$env", "qa%1", "qa&test", "qa(test)"]
        for env in invalid_chars:
            with pytest.raises(ValidationError) as exc_info:
                PropertyItem(environment=env, keys="test-app", properties={"key": "value"})
            assert "invalid characters" in str(exc_info.value).lower()

    def test_invalid_characters_in_key(self):
        """Test that invalid characters in key fail"""
        invalid_chars = ["test/app", "app@key", "key#1", "app$name", "key&value"]
        for key in invalid_chars:
            with pytest.raises(ValidationError) as exc_info:
                PropertyItem(environment="qa", keys=key, properties={"key": "value"})
            assert "invalid characters" in str(exc_info.value).lower()

    def test_valid_special_characters(self):
        """Test that hyphens, underscores, dots are allowed"""
        test_cases = [
            ("qa-env_1.0", "test-app_v1.2"),
            ("prod-1.0", "my_app-2.3"),
            ("dev_1.0.0", "service.key"),
        ]

        for env, key in test_cases:
            item = PropertyItem(environment=env, keys=key, properties={"key": "value"})
            assert item.environment == env
            assert item.keys_ == key

    def test_too_many_properties(self):
        """Test that more than max properties fails"""
        properties = {f"key{i}": f"value{i}" for i in range(Config.MAX_PROPERTIES_PER_REQUEST + 1)}
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="test-app", properties=properties)
        assert (
            f"maximum {Config.MAX_PROPERTIES_PER_REQUEST} properties" in str(exc_info.value).lower()
        )

    def test_property_key_too_long(self):
        """Test that property key exceeding max chars fails"""
        long_key = "a" * (Config.MAX_SECRET_NAME_LENGTH + 1)
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="test-app", properties={long_key: "value"})
        assert "property key too long" in str(exc_info.value).lower()

    def test_property_value_too_long(self):
        """Test that property value exceeding max chars fails"""
        long_value = "a" * (Config.MAX_SECRET_VALUE_LENGTH + 1)
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="test-app", properties={"key": long_value})
        assert "property value too long" in str(exc_info.value).lower()

    def test_empty_property_value_fails(self):
        """Test that empty property value fails"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="qa", keys="test-app", properties={"key": ""})
        assert "cannot be empty" in str(exc_info.value).lower()

    def test_multiple_validation_errors(self):
        """Test that multiple validation errors are captured"""
        with pytest.raises(ValidationError) as exc_info:
            PropertyItem(environment="", keys="", properties={})

        error_str = str(exc_info.value)
        assert "Environment cannot be empty" in error_str
        assert "Keys cannot be empty" in error_str
        assert "Properties dictionary cannot be empty" in error_str

    def test_strip_whitespace(self):
        """Test that whitespace is stripped from environment and key"""
        item = PropertyItem(
            environment="  qa  ", keys="  test-app  ", properties={"key1": "value1"}
        )
        assert item.environment == "qa"
        assert item.keys_ == "test-app"

    def test_dict_serialization(self):
        """Test that model can be serialized to dict"""
        item = PropertyItem(environment="qa", keys="test-app", properties={"key1": "value1"})
        item_dict = item.dict(by_alias=True)
        assert item_dict["environment"] == "qa"
        assert item_dict["keys"] == "test-app"
        assert item_dict["properties"] == {"key1": "value1"}

    def test_json_serialization(self):
        """Test that model can be serialized to JSON"""
        item = PropertyItem(environment="qa", keys="test-app", properties={"key1": "value1"})
        json_str = item.json(by_alias=True)
        data = json.loads(json_str)
        assert data["environment"] == "qa"
        assert data["keys"] == "test-app"
        assert data["properties"] == {"key1": "value1"}
