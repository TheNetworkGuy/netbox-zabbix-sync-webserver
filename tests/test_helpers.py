"""Tests for the convert_config_types helper and CLI entry point."""


class TestConvertConfigTypes:
    def test_boolean_true(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({"clustering": "true"}) == {"clustering": True}

    def test_boolean_false(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({"clustering": "false"}) == {"clustering": False}

    def test_boolean_case_insensitive(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({"a": "True", "b": "FALSE"}) == {"a": True, "b": False}

    def test_integer_conversion(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({"port": "8080"}) == {"port": 8080}

    def test_string_passthrough(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({"name": "hello"}) == {"name": "hello"}

    def test_mixed_values(self):
        from app.sync_manager import convert_config_types

        raw = {"flag": "true", "count": "42", "label": "test"}
        assert convert_config_types(raw) == {"flag": True, "count": 42, "label": "test"}

    def test_empty_dict(self):
        from app.sync_manager import convert_config_types

        assert convert_config_types({}) == {}

    def test_non_string_passthrough(self):
        """Non-string values should pass through unchanged."""
        from app.sync_manager import convert_config_types

        raw = {"flag": True, "count": 42, "str_val": "hello"}
        assert convert_config_types(raw) == {"flag": True, "count": 42, "str_val": "hello"}
