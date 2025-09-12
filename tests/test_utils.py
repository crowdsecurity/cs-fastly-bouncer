import logging
import sys
import unittest
from io import StringIO
from unittest.mock import patch

from fastly_bouncer.utils import (
    DEFAULT_DECISION_SOURCES,
    SUPPORTED_ACTIONS,
    VERSION,
    CustomFormatter,
    are_filled_validator,
    get_default_logger,
    with_suffix,
)


class TestCustomFormatter(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.formatter = CustomFormatter()

    def test_format_error_level(self):
        """Test formatting ERROR level messages"""
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test error message",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)

        # Should include timestamp, level, and message but not filename/lineno for ERROR
        self.assertIn("ERROR", result)
        self.assertIn("Test error message", result)
        self.assertNotIn("file.py:42", result)

    def test_format_warning_level(self):
        """Test formatting WARNING level messages"""
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test warning message",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)

        # Should include timestamp, level, and message but not filename/lineno for WARNING
        self.assertIn("WARNING", result)
        self.assertIn("Test warning message", result)
        self.assertNotIn("file.py:42", result)

    def test_format_debug_level(self):
        """Test formatting DEBUG level messages"""
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test debug message",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)

        # Should include timestamp, level, message, AND filename/lineno for DEBUG
        self.assertIn("DEBUG", result)
        self.assertIn("Test debug message", result)
        self.assertIn("file.py:42", result)

    def test_format_info_level_default(self):
        """Test formatting INFO level messages (uses default format)"""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="/path/to/file.py",
            lineno=42,
            msg="Test info message",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)

        # Should use default format for INFO level
        self.assertIn("INFO", result)
        self.assertIn("Test info message", result)
        self.assertNotIn("file.py:42", result)

    def test_formats_constants(self):
        """Test that FORMATS dictionary has expected keys"""
        expected_keys = {logging.ERROR, logging.WARNING, logging.DEBUG, "DEFAULT"}
        actual_keys = set(self.formatter.FORMATS.keys())

        self.assertEqual(actual_keys, expected_keys)

        # Verify each format contains expected placeholders
        for format_str in self.formatter.FORMATS.values():
            self.assertIn("%(asctime)s", format_str)
            self.assertIn("%(levelname)s", format_str)
            self.assertIn("%(message)s", format_str)


class TestWithSuffix(unittest.TestCase):
    def test_with_suffix_single_kwarg(self):
        """Test with_suffix with a single keyword argument"""
        result = with_suffix("Processing request", service_id="svc123")

        self.assertEqual(result, "Processing request service_id=svc123")

    def test_with_suffix_multiple_kwargs(self):
        """Test with_suffix with multiple keyword arguments"""
        result = with_suffix(
            "Processing request", service_id="svc123", version="2", action="ban"
        )

        # Arguments should be sorted alphabetically
        expected = "Processing request action=ban service_id=svc123 version=2"
        self.assertEqual(result, expected)

    def test_with_suffix_no_kwargs(self):
        """Test with_suffix with no keyword arguments"""
        result = with_suffix("Simple message")

        self.assertEqual(result, "Simple message ")

    def test_with_suffix_empty_string(self):
        """Test with_suffix with empty base string"""
        result = with_suffix("", service_id="svc123", action="captcha")

        expected = " action=captcha service_id=svc123"
        self.assertEqual(result, expected)

    def test_with_suffix_numeric_values(self):
        """Test with_suffix with numeric values"""
        result = with_suffix("Stats", count=42, rate=3.14)

        expected = "Stats count=42 rate=3.14"
        self.assertEqual(result, expected)

    def test_with_suffix_special_characters(self):
        """Test with_suffix with special characters in values"""
        result = with_suffix(
            "Message", path="/var/log/file.log", query="name=test&active=true"
        )

        # Keys should be sorted, values should be preserved as-is
        expected = "Message path=/var/log/file.log query=name=test&active=true"
        self.assertEqual(result, expected)


class TestAreFilledValidator(unittest.TestCase):
    def test_are_filled_validator_all_filled(self):
        """Test validator with all fields filled"""
        # Should not raise any exception
        try:
            are_filled_validator(name="test", value="data", count=42)
        except ValueError:
            self.fail("are_filled_validator raised ValueError unexpectedly")

    def test_are_filled_validator_none_value(self):
        """Test validator with None value raises exception"""
        with self.assertRaises(ValueError) as context:
            are_filled_validator(name="test", value=None, count=42)

        self.assertIn("value is not specified in config", str(context.exception))

    def test_are_filled_validator_multiple_none(self):
        """Test validator with multiple None values raises for first one"""
        with self.assertRaises(ValueError) as context:
            are_filled_validator(name=None, value=None, count=42)

        # Should raise for the first None value encountered (order may vary)
        error_msg = str(context.exception)
        self.assertTrue(
            "name is not specified in config" in error_msg
            or "value is not specified in config" in error_msg
        )

    def test_are_filled_validator_empty_string(self):
        """Test validator with empty string (should pass)"""
        try:
            are_filled_validator(name="", value="test")
        except ValueError:
            self.fail("are_filled_validator raised ValueError for empty string")

    def test_are_filled_validator_zero_value(self):
        """Test validator with zero value (should pass)"""
        try:
            are_filled_validator(count=0, rate=0.0, enabled=False)
        except ValueError:
            self.fail("are_filled_validator raised ValueError for zero/false values")

    def test_are_filled_validator_no_args(self):
        """Test validator with no arguments"""
        try:
            are_filled_validator()
        except ValueError:
            self.fail("are_filled_validator raised ValueError with no arguments")


class TestGetDefaultLogger(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        # Clear any existing handlers to avoid interference
        root_logger = logging.getLogger("")
        root_logger.handlers.clear()

    def tearDown(self):
        """Clean up after tests"""
        # Clear handlers added during tests
        root_logger = logging.getLogger("")
        root_logger.handlers.clear()

    def test_get_default_logger_returns_logger(self):
        """Test that get_default_logger returns a logger instance"""
        logger = get_default_logger()

        self.assertIsInstance(logger, logging.Logger)
        # Root logger name can be "" or "root" depending on Python version
        self.assertIn(logger.name, ["", "root"])

    def test_get_default_logger_adds_handler(self):
        """Test that get_default_logger adds a StreamHandler"""
        logger = get_default_logger()

        self.assertEqual(len(logger.handlers), 1)
        handler = logger.handlers[0]
        self.assertIsInstance(handler, logging.StreamHandler)
        self.assertEqual(handler.stream, sys.stdout)

    def test_get_default_logger_uses_custom_formatter(self):
        """Test that get_default_logger uses CustomFormatter"""
        logger = get_default_logger()

        handler = logger.handlers[0]
        self.assertIsInstance(handler.formatter, CustomFormatter)

    @patch("sys.stdout", new_callable=StringIO)
    def test_get_default_logger_output_format(self, mock_stdout):
        """Test that the logger produces correctly formatted output"""
        logger = get_default_logger()
        logger.setLevel(logging.INFO)

        logger.info("Test message")

        output = mock_stdout.getvalue()
        self.assertIn("INFO", output)
        self.assertIn("Test message", output)
        # Should contain timestamp pattern (basic check)
        self.assertTrue(any(char.isdigit() for char in output))


class TestConstants(unittest.TestCase):
    def test_supported_actions(self):
        """Test SUPPORTED_ACTIONS constant"""
        self.assertIsInstance(SUPPORTED_ACTIONS, list)
        self.assertIn("ban", SUPPORTED_ACTIONS)
        self.assertIn("captcha", SUPPORTED_ACTIONS)
        self.assertEqual(len(SUPPORTED_ACTIONS), 2)

    def test_default_decision_sources(self):
        """Test DEFAULT_DECISION_SOURCES constant"""
        self.assertIsInstance(DEFAULT_DECISION_SOURCES, list)
        self.assertIn("crowdsec", DEFAULT_DECISION_SOURCES)
        self.assertIn("cscli", DEFAULT_DECISION_SOURCES)
        self.assertEqual(len(DEFAULT_DECISION_SOURCES), 2)

    def test_version_is_string(self):
        """Test VERSION constant is a string"""
        self.assertIsInstance(VERSION, str)
        # Basic version format check (should contain at least one dot)
        self.assertIn(".", VERSION)


if __name__ == "__main__":
    unittest.main()
