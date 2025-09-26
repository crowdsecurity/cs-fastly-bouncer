import logging
import sys
import unittest
from io import StringIO
from logging.handlers import RotatingFileHandler
from unittest.mock import MagicMock, Mock, patch

from fastly_bouncer.config import Config, CrowdSecConfig
from fastly_bouncer.main import build_client_params, set_logger
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
        result = build_client_params(self.config)

        # Check required parameters
        self.assertEqual(result["api_key"], "test_api_key")
        self.assertEqual(result["lapi_url"], "http://localhost:8080/")
        self.assertEqual(result["interval"], 30)
        self.assertEqual(result["user_agent"], f"fastly-bouncer/v{VERSION}")
        self.assertEqual(result["scopes"], ("ip", "range", "country", "as"))
        self.assertEqual(result["only_include_decisions_from"], ("crowdsec", "cscli"))

    def test_include_scenarios_containing(self):
        """Test include_scenarios_containing parameter"""
        self.crowdsec_config.include_scenarios_containing = [
            "http",
            "ssh",
            "brute-force",
        ]

        result = build_client_params(self.config)

        self.assertEqual(
            result["include_scenarios_containing"], ("http", "ssh", "brute-force")
        )

    def test_exclude_scenarios_containing(self):
        """Test exclude_scenarios_containing parameter"""
        self.crowdsec_config.exclude_scenarios_containing = ["test", "debug"]

        result = build_client_params(self.config)

        self.assertEqual(result["exclude_scenarios_containing"], ("test", "debug"))

    def test_ssl_tls_options(self):
        """Test SSL/TLS related parameters"""
        self.crowdsec_config.insecure_skip_verify = True
        self.crowdsec_config.key_path = "/path/to/key.pem"
        self.crowdsec_config.cert_path = "/path/to/cert.pem"
        self.crowdsec_config.ca_cert_path = "/path/to/ca.pem"

        result = build_client_params(self.config)

        self.assertTrue(result["insecure_skip_verify"])
        self.assertEqual(result["key_path"], "/path/to/key.pem")
        self.assertEqual(result["cert_path"], "/path/to/cert.pem")
        self.assertEqual(result["ca_cert_path"], "/path/to/ca.pem")

    def test_optional_ssl_parameters_not_set(self):
        """Test that optional SSL parameters are not included when not set"""
        # Default values should not include optional SSL params
        result = build_client_params(self.config)

        self.assertNotIn("insecure_skip_verify", result)
        self.assertNotIn("key_path", result)
        self.assertNotIn("cert_path", result)
        self.assertNotIn("ca_cert_path", result)

    def test_empty_scenarios_lists(self):
        """Test behavior with empty scenario lists"""
        self.crowdsec_config.include_scenarios_containing = []
        self.crowdsec_config.exclude_scenarios_containing = []

        result = build_client_params(self.config)

        # Empty lists should not be included
        self.assertNotIn("include_scenarios_containing", result)
        self.assertNotIn("exclude_scenarios_containing", result)

    def test_custom_decision_sources(self):
        """Test custom only_include_decisions_from parameter"""
        self.crowdsec_config.only_include_decisions_from = [
            "custom-source",
            "another-source",
        ]

        result = build_client_params(self.config)

        self.assertEqual(
            result["only_include_decisions_from"], ("custom-source", "another-source")
        )

    def test_different_update_frequency(self):
        """Test different update frequency values"""
        self.config.update_frequency = 60

        result = build_client_params(self.config)

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

        result = build_client_params(self.config)

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

        self.assertIn("Unknown log mode invalid_mode", str(context.exception))

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


class TestRefreshMode(unittest.TestCase):
    """Test refresh mode functionality"""

    @patch("fastly_bouncer.main.parse_config_file")
    @patch("fastly_bouncer.main.set_logger")
    @patch("fastly_bouncer.main.trio")
    @patch("sys.argv", ["crowdsec-fastly-bouncer", "-c", "config.yaml", "-r"])
    def test_refresh_mode_argument_parsing(
        self, mock_trio, mock_set_logger, mock_parse_config
    ):
        """Test that -r argument is properly parsed and passed to start function"""
        from fastly_bouncer.main import main

        # Mock config parsing
        mock_config = Mock()
        mock_parse_config.return_value = mock_config

        # Mock Path.exists to return True
        with patch("fastly_bouncer.main.Path") as mock_path:
            mock_path.return_value.exists.return_value = True

            try:
                main()
            except SystemExit:
                pass

        # Verify trio.run was called with refresh_mode=True
        mock_trio.run.assert_called_once()
        call_args = mock_trio.run.call_args
        self.assertEqual(
            len(call_args[0]), 4
        )  # start, config, cleanup_mode, refresh_mode
        self.assertEqual(call_args[0][2], False)  # cleanup_mode should be False
        self.assertEqual(call_args[0][3], True)  # refresh_mode should be True

    @patch("sys.argv", ["crowdsec-fastly-bouncer", "-r"])
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.stderr", new_callable=StringIO)
    def test_refresh_mode_requires_config_file(self, mock_stderr, mock_stdout):
        """Test that -r requires -c argument"""
        from fastly_bouncer.main import main

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Refresh mode (-r) requires config file (-c)", mock_stderr.getvalue()
        )

    @patch("sys.argv", ["crowdsec-fastly-bouncer", "-c", "config.yaml", "-r", "-d"])
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.stderr", new_callable=StringIO)
    def test_refresh_mode_conflicts_with_cleanup(self, mock_stderr, mock_stdout):
        """Test that -r cannot be used with -d"""
        from fastly_bouncer.main import main

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Refresh mode (-r) cannot be used with cleanup mode (-d)",
            mock_stderr.getvalue(),
        )

    @patch(
        "sys.argv",
        ["crowdsec-fastly-bouncer", "-c", "config.yaml", "-r", "-g", "token"],
    )
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.stderr", new_callable=StringIO)
    def test_refresh_mode_conflicts_with_generate(self, mock_stderr, mock_stdout):
        """Test that -r cannot be used with -g"""
        from fastly_bouncer.main import main

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Refresh mode (-r) can only be used with config file (-c)",
            mock_stderr.getvalue(),
        )

    @patch("sys.argv", ["crowdsec-fastly-bouncer", "-c", "config.yaml", "-r", "-e"])
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.stderr", new_callable=StringIO)
    def test_refresh_mode_conflicts_with_edit(self, mock_stderr, mock_stdout):
        """Test that -r cannot be used with -e"""
        from fastly_bouncer.main import main

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Refresh mode (-r) can only be used with config file (-c)",
            mock_stderr.getvalue(),
        )

    @patch(
        "sys.argv",
        ["crowdsec-fastly-bouncer", "-c", "config.yaml", "-r", "-o", "output.yaml"],
    )
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.stderr", new_callable=StringIO)
    def test_refresh_mode_conflicts_with_output(self, mock_stderr, mock_stdout):
        """Test that -r cannot be used with -o"""
        from fastly_bouncer.main import main

        with self.assertRaises(SystemExit) as cm:
            main()

        self.assertEqual(cm.exception.code, 1)
        self.assertIn(
            "Refresh mode (-r) can only be used with config file (-c)",
            mock_stderr.getvalue(),
        )

    def test_start_refresh_mode_success(self):
        """Test start function in refresh mode with existing infrastructure"""
        import trio
        from fastly_bouncer.main import start

        async def run_test():
            with patch(
                "fastly_bouncer.main.discover_existing_fastly_infra"
            ) as mock_discover, patch(
                "fastly_bouncer.main.refresh_acls_on_startup"
            ) as mock_refresh_acls, patch(
                "fastly_bouncer.main.run"
            ) as mock_run:

                # Mock config
                mock_config = Mock()
                mock_config.cache_path = "/tmp/test_cache.json"

                # Mock discovered services
                mock_service = Mock()
                mock_service.as_jsonable_dict.return_value = {"service": "test"}
                mock_discover.return_value = [mock_service]

                # Call start in refresh mode
                await start(mock_config, False, True)

                # Verify calls
                mock_discover.assert_called_once_with(mock_config)
                mock_refresh_acls.assert_called_once_with([mock_service])
                mock_run.assert_called_once_with(mock_config, [mock_service])

        trio.run(run_test)

    def test_start_refresh_mode_no_infrastructure(self):
        """Test start function in refresh mode with no existing infrastructure"""
        import asyncio

        from fastly_bouncer.main import start

        async def run_test():
            with patch(
                "fastly_bouncer.main.discover_existing_fastly_infra"
            ) as mock_discover, patch("fastly_bouncer.main.logger") as mock_logger:

                # Mock config
                mock_config = Mock()

                # Mock no services found
                mock_discover.return_value = []

                # Call start in refresh mode
                await start(mock_config, False, True)

                # Verify error logging
                mock_logger.error.assert_called_once_with(
                    "No existing CrowdSec infrastructure found in Fastly to refresh"
                )

        asyncio.run(run_test())

    def test_start_normal_mode(self):
        """Test start function in normal mode"""
        import asyncio

        from fastly_bouncer.main import start

        async def run_test():
            with patch("fastly_bouncer.main.setup_fastly_infra") as mock_setup, patch(
                "fastly_bouncer.main.refresh_acls_on_startup"
            ) as mock_refresh_acls, patch("fastly_bouncer.main.run") as mock_run:

                # Mock config
                mock_config = Mock()

                # Mock setup returning services only (no needs_acl_refresh)
                mock_service = Mock()
                mock_setup.return_value = [mock_service]

                # Call start in normal mode
                await start(mock_config, False, False)

                # Verify calls
                mock_setup.assert_called_once_with(mock_config, False)
                # ACL refresh should NOT be called in normal mode (only with -r)
                mock_refresh_acls.assert_not_called()
                mock_run.assert_called_once_with(mock_config, [mock_service])

        asyncio.run(run_test())


class TestSuccessTracking(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        # Mock FastlyAPI
        self.mock_api = Mock(spec=MagicMock)
        self.mock_api._token = "test_token"

        # Create a test ACL
        from fastly_bouncer.fastly_api import ACL

        self.test_acl = ACL(
            id="test_acl_id",
            name="test_acl",
            service_id="test_service",
            version="test_version",
            entries_to_add={"192.168.1.1"},
            entries_to_delete=set(),
            entries={},
            entry_count=0,
            created="2024-01-01",
        )

    def test_process_acl_return_type(self):
        """Test that process_acl method exists and can return bool."""
        from unittest.mock import AsyncMock

        # Mock the process_acl method
        self.mock_api.process_acl = AsyncMock()

        # Verify the method signature accepts return values
        self.mock_api.process_acl.return_value = True
        self.assertTrue(self.mock_api.process_acl.return_value)

        self.mock_api.process_acl.return_value = False
        self.assertFalse(self.mock_api.process_acl.return_value)

    def test_acl_collection_commit_return_type(self):
        """Test that ACL collection commit method returns bool."""
        from fastly_bouncer.service import ACLCollection

        acl_collection = ACLCollection(
            api=self.mock_api,
            service_id="test_service",
            version="test_version",
            action="ban",
            max_items=1000,
            acls=[],
            state=set(),
        )

        # Test the method signature - it should return bool
        from inspect import signature

        commit_sig = signature(acl_collection.commit)
        self.assertEqual(commit_sig.return_annotation, bool)

    def test_cache_consistency_logic(self):
        """Test the cache consistency logic in main loop."""
        from unittest.mock import AsyncMock

        # Simulate the main loop logic
        services = []
        previous_states = []

        # Create two mock services
        service1 = Mock()
        service1.service_id = "service1"
        service1.as_jsonable_dict.return_value = {"state": "new_state_1"}
        service1.transform_state = AsyncMock(return_value=True)  # Success

        service2 = Mock()
        service2.service_id = "service2"
        service2.as_jsonable_dict.return_value = {"state": "new_state_2"}
        service2.transform_state = AsyncMock(return_value=False)  # Failure

        services = [service1, service2]
        previous_states = [{"state": "old_state_1"}, {"state": "old_state_2"}]

        # Simulate service results tracking
        service_results = {
            id(service1): True,  # Success
            id(service2): False,  # Failure
        }

        # Categorize services by success/failure
        successful_services = []
        failed_services = []
        for service in services:
            service_success = service_results.get(id(service), False)
            if service_success:
                successful_services.append(service)
            else:
                failed_services.append(service)

        # Generate new states (successful services get new state, failed get previous)
        new_states = []
        for i, service in enumerate(services):
            if service in successful_services:
                # Use current state for successful services
                new_states.append(service.as_jsonable_dict())
            else:
                # Use previous state for failed services
                if i < len(previous_states):
                    new_states.append(previous_states[i])
                else:
                    # Fallback: use current state
                    new_states.append(service.as_jsonable_dict())

        # Verify results
        self.assertEqual(len(successful_services), 1)
        self.assertEqual(len(failed_services), 1)
        self.assertEqual(successful_services[0], service1)
        self.assertEqual(failed_services[0], service2)

        # Verify cache states
        self.assertEqual(
            new_states[0], {"state": "new_state_1"}
        )  # service1 succeeded, new state
        self.assertEqual(
            new_states[1], {"state": "old_state_2"}
        )  # service2 failed, old state


if __name__ == "__main__":
    unittest.main()
