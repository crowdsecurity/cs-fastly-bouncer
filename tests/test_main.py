import logging
import sys
import unittest
from logging.handlers import RotatingFileHandler
from unittest.mock import MagicMock, patch

from fastly_bouncer.config import Config, CrowdSecConfig
from fastly_bouncer.main import buildClientParams, set_logger
from fastly_bouncer.utils import VERSION, CustomFormatter


class TestBuildClientParams(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.crowdsec_config = CrowdSecConfig(
            lapi_key="test_api_key", lapi_url="http://localhost:8080/"
        )
        self.config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=30,
            crowdsec_config=self.crowdsec_config,
            fastly_account_configs=[],
        )

    def test_basic_client_params(self):
        """Test basic client parameters generation"""
        result = buildClientParams(self.config)

        # Check required parameters
        self.assertEqual(result["api_key"], "test_api_key")
        self.assertEqual(result["lapi_url"], "http://localhost:8080/")
        self.assertEqual(result["interval"], 30)
        self.assertEqual(result["user_agent"], f"fastly-bouncer/v{VERSION}")
        self.assertEqual(result["scopes"], ("ip", "range", "country", "as"))
        self.assertEqual(result["only_include_decisions_from"], ("crowdsec", "cscli"))

    def test_include_scenarios_containing(self):
        """Test include_scenarios_containing parameter"""
        self.crowdsec_config.include_scenarios_containing = ["http", "ssh", "brute-force"]

        result = buildClientParams(self.config)

        self.assertEqual(result["include_scenarios_containing"], ("http", "ssh", "brute-force"))

    def test_exclude_scenarios_containing(self):
        """Test exclude_scenarios_containing parameter"""
        self.crowdsec_config.exclude_scenarios_containing = ["test", "debug"]

        result = buildClientParams(self.config)

        self.assertEqual(result["exclude_scenarios_containing"], ("test", "debug"))

    def test_ssl_tls_options(self):
        """Test SSL/TLS related parameters"""
        self.crowdsec_config.insecure_skip_verify = True
        self.crowdsec_config.key_path = "/path/to/key.pem"
        self.crowdsec_config.cert_path = "/path/to/cert.pem"
        self.crowdsec_config.ca_cert_path = "/path/to/ca.pem"

        result = buildClientParams(self.config)

        self.assertTrue(result["insecure_skip_verify"])
        self.assertEqual(result["key_path"], "/path/to/key.pem")
        self.assertEqual(result["cert_path"], "/path/to/cert.pem")
        self.assertEqual(result["ca_cert_path"], "/path/to/ca.pem")

    def test_optional_ssl_parameters_not_set(self):
        """Test that optional SSL parameters are not included when not set"""
        # Default values should not include optional SSL params
        result = buildClientParams(self.config)

        self.assertNotIn("insecure_skip_verify", result)
        self.assertNotIn("key_path", result)
        self.assertNotIn("cert_path", result)
        self.assertNotIn("ca_cert_path", result)

    def test_empty_scenarios_lists(self):
        """Test behavior with empty scenario lists"""
        self.crowdsec_config.include_scenarios_containing = []
        self.crowdsec_config.exclude_scenarios_containing = []

        result = buildClientParams(self.config)

        # Empty lists should not be included
        self.assertNotIn("include_scenarios_containing", result)
        self.assertNotIn("exclude_scenarios_containing", result)

    def test_custom_decision_sources(self):
        """Test custom only_include_decisions_from parameter"""
        self.crowdsec_config.only_include_decisions_from = ["custom-source", "another-source"]

        result = buildClientParams(self.config)

        self.assertEqual(result["only_include_decisions_from"], ("custom-source", "another-source"))

    def test_different_update_frequency(self):
        """Test different update frequency values"""
        self.config.update_frequency = 60

        result = buildClientParams(self.config)

        self.assertEqual(result["interval"], 60)

    def test_all_optional_parameters_set(self):
        """Test when all optional parameters are set"""
        self.crowdsec_config.include_scenarios_containing = ["web"]
        self.crowdsec_config.exclude_scenarios_containing = ["internal"]
        self.crowdsec_config.insecure_skip_verify = True
        self.crowdsec_config.key_path = "/key.pem"
        self.crowdsec_config.cert_path = "/cert.pem"
        self.crowdsec_config.ca_cert_path = "/ca.pem"
        self.crowdsec_config.only_include_decisions_from = ["source1", "source2"]
        self.config.update_frequency = 120

        result = buildClientParams(self.config)

        # Verify all parameters are present
        expected_keys = {
            "api_key",
            "lapi_url",
            "interval",
            "user_agent",
            "scopes",
            "only_include_decisions_from",
            "include_scenarios_containing",
            "exclude_scenarios_containing",
            "insecure_skip_verify",
            "key_path",
            "cert_path",
            "ca_cert_path",
        }
        self.assertEqual(set(result.keys()), expected_keys)


class TestSetLogger(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        # Create a test logger and clear its handlers
        self.test_logger = logging.getLogger("test_logger")
        self.test_logger.handlers.clear()

        # Create basic config
        self.crowdsec_config = CrowdSecConfig(
            lapi_key="test_key", lapi_url="http://localhost:8080/"
        )
        self.config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=30,
            crowdsec_config=self.crowdsec_config,
            fastly_account_configs=[],
        )

    def tearDown(self):
        """Clean up after tests"""
        self.test_logger.handlers.clear()

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_stdout(self, mock_logger):
        """Test logger setup with stdout mode"""
        mock_logger.handlers = []
        self.config.log_mode = "stdout"
        self.config.log_level = "debug"

        set_logger(self.config)

        # Verify logger configuration
        mock_logger.setLevel.assert_called_once_with(logging.DEBUG)
        mock_logger.addHandler.assert_called_once()
        mock_logger.info.assert_called_once_with(f"Starting fastly-bouncer-v{VERSION}")

        # Check that a StreamHandler was created (can't verify sys.stdout directly due to mocking)
        handler_call = mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler_call, logging.StreamHandler)

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_stderr(self, mock_logger):
        """Test logger setup with stderr mode"""
        mock_logger.handlers = []
        self.config.log_mode = "stderr"
        self.config.log_level = "warning"

        set_logger(self.config)

        mock_logger.setLevel.assert_called_once_with(logging.WARNING)
        mock_logger.addHandler.assert_called_once()

        # Verify StreamHandler with stderr
        handler_call = mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler_call, logging.StreamHandler)
        self.assertEqual(handler_call.stream, sys.stderr)

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_file(self, mock_logger):
        """Test logger setup with file mode"""
        mock_logger.handlers = []
        self.config.log_mode = "file"
        self.config.log_file = "/tmp/test.log"
        self.config.log_level = "error"

        set_logger(self.config)

        mock_logger.setLevel.assert_called_once_with(logging.ERROR)
        mock_logger.addHandler.assert_called_once()

        # Verify RotatingFileHandler was created and close it to prevent ResourceWarning
        handler_call = mock_logger.addHandler.call_args[0][0]
        self.assertIsInstance(handler_call, RotatingFileHandler)
        handler_call.close()

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_unknown_mode(self, mock_logger):
        """Test logger setup with unknown mode raises ValueError"""
        mock_logger.handlers = []
        self.config.log_mode = "invalid_mode"

        with self.assertRaises(ValueError) as context:
            set_logger(self.config)

        self.assertIn("unknown log mode invalid_mode", str(context.exception))

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_removes_existing_handlers(self, mock_logger):
        """Test that existing handlers are removed"""
        # Mock existing handlers
        mock_handler1 = MagicMock()
        mock_handler2 = MagicMock()
        mock_logger.handlers = [mock_handler1, mock_handler2]

        self.config.log_mode = "stdout"

        set_logger(self.config)

        # Verify removeHandler was called for each existing handler
        mock_logger.removeHandler.assert_any_call(mock_handler1)
        mock_logger.removeHandler.assert_any_call(mock_handler2)

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_uses_custom_formatter(self, mock_logger):
        """Test that CustomFormatter is applied to the handler"""
        mock_logger.handlers = []
        self.config.log_mode = "stdout"

        set_logger(self.config)

        # Get the handler that was added
        handler_call = mock_logger.addHandler.call_args[0][0]

        # Verify CustomFormatter was set
        self.assertIsInstance(handler_call.formatter, CustomFormatter)

    @patch("fastly_bouncer.main.logger")
    def test_set_logger_different_log_levels(self, mock_logger):
        """Test logger setup with different log levels"""
        mock_logger.handlers = []

        test_cases = [
            ("debug", logging.DEBUG),
            ("info", logging.INFO),
            ("warning", logging.WARNING),
            ("error", logging.ERROR),
        ]

        for log_level_str, expected_level in test_cases:
            with self.subTest(log_level=log_level_str):
                mock_logger.reset_mock()
                self.config.log_level = log_level_str
                self.config.log_mode = "stdout"

                set_logger(self.config)

                mock_logger.setLevel.assert_called_once_with(expected_level)

    def test_config_get_log_level_method(self):
        """Test the get_log_level method of Config class"""
        test_cases = [
            ("debug", logging.DEBUG),
            ("info", logging.INFO),
            ("warning", logging.WARNING),
            ("error", logging.ERROR),
            ("DEBUG", logging.DEBUG),  # Case insensitive
            ("Info", logging.INFO),
            ("WARNING", logging.WARNING),
            ("invalid", None),  # Invalid level should return None
        ]

        for log_level_str, expected_level in test_cases:
            with self.subTest(log_level=log_level_str):
                self.config.log_level = log_level_str
                result = self.config.get_log_level()
                self.assertEqual(result, expected_level)


if __name__ == "__main__":
    unittest.main()
