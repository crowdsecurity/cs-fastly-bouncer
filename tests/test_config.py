import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import yaml
from fastly_bouncer.config import (
    Config,
    ConfigGenerator,
    CrowdSecConfig,
    FastlyAccountConfig,
    FastlyServiceConfig,
    fastly_config_from_dict,
    parse_config_file,
)


class TestConfigGeneration(TestCase):
    def test_crowdsec_config_validation(self):
        """Test CrowdSecConfig validates required fields"""
        # Valid config should not raise
        config = CrowdSecConfig(lapi_key="test_key", lapi_url="http://localhost:8080/")
        self.assertEqual(config.lapi_key, "test_key")
        self.assertEqual(config.lapi_url, "http://localhost:8080/")

        # None lapi_key should raise (are_filled_validator checks for None, not empty strings)
        with self.assertRaises(ValueError) as context:
            CrowdSecConfig(lapi_key=None, lapi_url="http://localhost:8080/")
        self.assertIn("lapi_key is not specified", str(context.exception))

    def test_fastly_service_config_validation(self):
        """Test FastlyServiceConfig validates required fields"""
        # Valid config should not raise
        config = FastlyServiceConfig(
            id="service123",
            recaptcha_site_key="site_key",
            recaptcha_secret_key="secret_key",
        )
        self.assertEqual(config.id, "service123")
        self.assertEqual(config.activate, False)  # Default value
        self.assertEqual(config.max_items, 20000)  # Default value

        # None required field should raise (are_filled_validator checks for None, not empty strings)
        with self.assertRaises(ValueError) as context:
            FastlyServiceConfig(
                id=None, recaptcha_site_key="site", recaptcha_secret_key="secret"
            )
        self.assertIn("id is not specified", str(context.exception))

    def test_config_validation(self):
        """Test Config validates account configurations"""
        crowdsec_config = CrowdSecConfig(lapi_key="test_key")

        # Valid config with account token and services
        service_config = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="site_key",
            recaptcha_secret_key="secret_key",
        )
        account_config = FastlyAccountConfig(
            account_token="token123", services=[service_config]
        )

        config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=10,
            crowdsec_config=crowdsec_config,
            fastly_account_configs=[account_config],
        )

        # Should not raise
        self.assertEqual(len(config.fastly_account_configs), 1)

        # Config with empty token should raise
        bad_account = FastlyAccountConfig(account_token="", services=[service_config])
        with self.assertRaises(ValueError) as context:
            Config(
                log_level="info",
                log_mode="stdout",
                log_file="/var/log/test.log",
                update_frequency=10,
                crowdsec_config=crowdsec_config,
                fastly_account_configs=[bad_account],
            )
        self.assertIn("no token specified", str(context.exception))

        # Config with no services should raise
        bad_account = FastlyAccountConfig(account_token="token123", services=[])
        with self.assertRaises(ValueError) as context:
            Config(
                log_level="info",
                log_mode="stdout",
                log_file="/var/log/test.log",
                update_frequency=10,
                crowdsec_config=crowdsec_config,
                fastly_account_configs=[bad_account],
            )
        self.assertIn("no service specified", str(context.exception))

    def test_parse_config_file(self):
        """Test parsing a YAML configuration file"""
        config_data = {
            "log_level": "debug",
            "log_mode": "file",
            "log_file": "/var/log/bouncer.log",
            "update_frequency": 30,
            "cache_path": "/tmp/cache.json",
            "crowdsec_config": {
                "lapi_key": "test_api_key",
                "lapi_url": "http://crowdsec:8080/",
                "include_scenarios_containing": ["http"],
                "exclude_scenarios_containing": ["ssh"],
                "insecure_skip_verify": True,
            },
            "fastly_account_configs": [
                {
                    "account_token": "fastly_token_123",
                    "services": [
                        {
                            "id": "service_id_1",
                            "recaptcha_site_key": "site_key_123",
                            "recaptcha_secret_key": "secret_key_456",
                            "activate": True,
                            "max_items": 15000,
                        }
                    ],
                }
            ],
        }

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            # Parse the config
            config = parse_config_file(temp_path)

            # Verify parsed values
            self.assertEqual(config.log_level, "debug")
            self.assertEqual(config.log_mode, "file")
            self.assertEqual(config.update_frequency, 30)
            self.assertEqual(config.crowdsec_config.lapi_key, "test_api_key")
            self.assertEqual(config.crowdsec_config.lapi_url, "http://crowdsec:8080/")
            self.assertTrue(config.crowdsec_config.insecure_skip_verify)
            self.assertEqual(
                config.crowdsec_config.include_scenarios_containing, ["http"]
            )
            self.assertEqual(
                config.crowdsec_config.exclude_scenarios_containing, ["ssh"]
            )

            # Verify account config
            self.assertEqual(len(config.fastly_account_configs), 1)
            account = config.fastly_account_configs[0]
            self.assertEqual(account.account_token, "fastly_token_123")
            self.assertEqual(len(account.services), 1)

            # Verify service config
            service = account.services[0]
            self.assertEqual(service.id, "service_id_1")
            self.assertTrue(service.activate)
            self.assertEqual(service.max_items, 15000)

        finally:
            # Clean up
            temp_path.unlink()

    def test_parse_config_file_not_found(self):
        """Test parsing non-existent config file raises FileNotFoundError"""
        non_existent_path = Path("/does/not/exist.yml")
        with self.assertRaises(FileNotFoundError):
            parse_config_file(non_existent_path)

    @patch("fastly_bouncer.config.ConfigGenerator.generate_config_for_account")
    def test_merge_service_configs(self, mock_generate_account):
        """Test merging existing and new service configurations"""
        # Mock the account generation
        mock_generate_account.return_value = FastlyAccountConfig(
            account_token="token123",
            services=[
                FastlyServiceConfig(
                    id="service1",
                    recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
                    recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
                    activate=False,
                )
            ],
        )

        # Existing config with customized service
        existing_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="real_site_key",
            recaptcha_secret_key="real_secret_key",
            activate=True,
            max_items=25000,
        )
        existing_account = FastlyAccountConfig(
            account_token="token123", services=[existing_service]
        )
        existing_config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=10,
            crowdsec_config=CrowdSecConfig(lapi_key="test"),
            fastly_account_configs=[existing_account],
        )

        # New config with default values
        new_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
            recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
            activate=False,
        )
        new_account = FastlyAccountConfig(
            account_token="token123", services=[new_service]
        )
        new_config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=10,
            crowdsec_config=CrowdSecConfig(lapi_key="test"),
            fastly_account_configs=[new_account],
        )

        # Merge configurations
        merged = ConfigGenerator.merge_service_configs(existing_config, new_config)

        # Verify merged service preserves existing values
        merged_service = merged.fastly_account_configs[0].services[0]
        self.assertEqual(merged_service.recaptcha_site_key, "real_site_key")
        self.assertEqual(merged_service.recaptcha_secret_key, "real_secret_key")
        self.assertTrue(merged_service.activate)
        self.assertEqual(merged_service.max_items, 25000)

    def test_fastly_service_config_with_reference_version(self):
        """Test FastlyServiceConfig with reference_version parameter"""
        service_config = FastlyServiceConfig(
            id="test_service",
            recaptcha_site_key="site_key",
            recaptcha_secret_key="secret_key",
            reference_version="42",
        )

        self.assertEqual(service_config.reference_version, "42")

    def test_fastly_service_config_with_none_reference_version(self):
        """Test FastlyServiceConfig with None reference_version (default)"""
        service_config = FastlyServiceConfig(
            id="test_service",
            recaptcha_site_key="site_key",
            recaptcha_secret_key="secret_key",
        )

        self.assertIsNone(service_config.reference_version)

    def test_merge_service_configs_with_reference_version(self):
        """Test merging preserves existing reference_version"""
        # Create existing config with reference_version
        existing_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="existing_site_key",
            recaptcha_secret_key="existing_secret",
            activate=True,
            reference_version="5",
        )
        existing_account = FastlyAccountConfig(
            account_token="existing_token", services=[existing_service]
        )
        existing_config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=30,
            crowdsec_config=CrowdSecConfig(lapi_key="test_key"),
            fastly_account_configs=[existing_account],
        )

        # Create new config with different reference_version
        new_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
            recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
            activate=False,
            reference_version="10",
        )
        new_account = FastlyAccountConfig(
            account_token="new_token", services=[new_service]
        )
        new_config = Config(
            log_level="debug",
            log_mode="file",
            log_file="/var/log/new.log",
            update_frequency=60,
            crowdsec_config=CrowdSecConfig(lapi_key="new_key"),
            fastly_account_configs=[new_account],
        )

        # Merge configurations
        merged_config = ConfigGenerator.merge_service_configs(
            existing_config, new_config
        )

        # Verify existing service config preserved including reference_version
        merged_service = merged_config.fastly_account_configs[0].services[0]
        self.assertEqual(merged_service.recaptcha_site_key, "existing_site_key")
        self.assertEqual(merged_service.recaptcha_secret_key, "existing_secret")
        self.assertTrue(merged_service.activate)  # Preserved from existing
        self.assertEqual(
            merged_service.reference_version, "5"
        )  # Preserved from existing config

    def test_merge_service_configs_with_none_reference_version(self):
        """Test merging preserves existing reference_version even when new config has None"""
        # Create existing config with reference_version
        existing_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="existing_site_key",
            recaptcha_secret_key="existing_secret",
            reference_version="5",
        )
        existing_account = FastlyAccountConfig(
            account_token="existing_token", services=[existing_service]
        )
        existing_config = Config(
            log_level="info",
            log_mode="stdout",
            log_file="/var/log/test.log",
            update_frequency=30,
            crowdsec_config=CrowdSecConfig(lapi_key="test_key"),
            fastly_account_configs=[existing_account],
        )

        # Create new config with None reference_version
        new_service = FastlyServiceConfig(
            id="service1",
            recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
            recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
            reference_version=None,
        )
        new_account = FastlyAccountConfig(
            account_token="new_token", services=[new_service]
        )
        new_config = Config(
            log_level="debug",
            log_mode="file",
            log_file="/var/log/new.log",
            update_frequency=60,
            crowdsec_config=CrowdSecConfig(lapi_key="new_key"),
            fastly_account_configs=[new_account],
        )

        # Merge configurations
        merged_config = ConfigGenerator.merge_service_configs(
            existing_config, new_config
        )

        # reference_version should be preserved from existing config, even when new is None
        merged_service = merged_config.fastly_account_configs[0].services[0]
        self.assertEqual(merged_service.reference_version, "5")

    def test_unknown_service_config_parameters_ignored(self):
        """Test that unknown service config parameters are ignored with warning"""
        import sys
        from io import StringIO

        # Capture stderr to check for warning
        captured_stderr = StringIO()
        original_stderr = sys.stderr
        sys.stderr = captured_stderr

        try:
            # Config data with unknown parameter
            service_data = {
                "id": "test_service",
                "recaptcha_site_key": "site_key",
                "recaptcha_secret_key": "secret_key",
                "activate": True,
                "clone_reference_version": True,  # Unknown parameter
                "old_param": "should_be_ignored",  # Another unknown parameter
            }

            account_data = [{"account_token": "token123", "services": [service_data]}]

            # This should not crash
            result = fastly_config_from_dict(account_data)

            # Verify it created the service successfully
            self.assertEqual(len(result), 1)
            service = result[0].services[0]
            self.assertEqual(service.id, "test_service")
            self.assertTrue(service.activate)

            # Verify warnings were printed
            stderr_output = captured_stderr.getvalue()
            self.assertIn("clone_reference_version", stderr_output)
            self.assertIn("old_param", stderr_output)
            self.assertIn("Warning:", stderr_output)

        finally:
            # Restore stderr
            sys.stderr = original_stderr

    def test_unknown_root_config_parameters_ignored(self):
        """Test that unknown root config parameters are ignored with warning"""
        import sys
        from io import StringIO

        # Capture stderr to check for warning
        captured_stderr = StringIO()
        original_stderr = sys.stderr
        sys.stderr = captured_stderr

        try:
            config_data = {
                "log_level": "debug",
                "log_mode": "file",
                "log_file": "/var/log/bouncer.log",
                "update_frequency": 30,
                "cache_path": "/tmp/cache.json",
                "old_root_param": "should_be_ignored",  # Unknown parameter
                "deprecated_setting": True,  # Another unknown parameter
                "crowdsec_config": {
                    "lapi_key": "test_api_key",
                    "lapi_url": "http://crowdsec:8080/",
                },
                "fastly_account_configs": [
                    {
                        "account_token": "fastly_token_123",
                        "services": [
                            {
                                "id": "service_id_1",
                                "recaptcha_site_key": "site_key_123",
                                "recaptcha_secret_key": "secret_key_456",
                            }
                        ],
                    }
                ],
            }

            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yml", delete=False
            ) as f:
                yaml.dump(config_data, f)
                temp_path = Path(f.name)

            try:
                # Parse the config - should not crash
                config = parse_config_file(temp_path)

                # Verify it parsed successfully
                self.assertEqual(config.log_level, "debug")
                self.assertEqual(config.update_frequency, 30)

                # Verify warnings were printed
                stderr_output = captured_stderr.getvalue()
                self.assertIn("old_root_param", stderr_output)
                self.assertIn("deprecated_setting", stderr_output)
                self.assertIn("Warning:", stderr_output)
                self.assertIn("root configuration", stderr_output)

            finally:
                # Clean up
                temp_path.unlink()

        finally:
            # Restore stderr
            sys.stderr = original_stderr

    def test_unknown_crowdsec_config_parameters_ignored(self):
        """Test that unknown crowdsec_config parameters are ignored with warning"""
        import sys
        from io import StringIO

        # Capture stderr to check for warning
        captured_stderr = StringIO()
        original_stderr = sys.stderr
        sys.stderr = captured_stderr

        try:
            config_data = {
                "log_level": "debug",
                "log_mode": "file",
                "log_file": "/var/log/bouncer.log",
                "update_frequency": 30,
                "cache_path": "/tmp/cache.json",
                "crowdsec_config": {
                    "lapi_key": "test_api_key",
                    "lapi_url": "http://crowdsec:8080/",
                    "old_crowdsec_param": "should_be_ignored",  # Unknown parameter
                    "deprecated_crowdsec_setting": False,  # Another unknown parameter
                },
                "fastly_account_configs": [
                    {
                        "account_token": "fastly_token_123",
                        "services": [
                            {
                                "id": "service_id_1",
                                "recaptcha_site_key": "site_key_123",
                                "recaptcha_secret_key": "secret_key_456",
                            }
                        ],
                    }
                ],
            }

            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yml", delete=False
            ) as f:
                yaml.dump(config_data, f)
                temp_path = Path(f.name)

            try:
                # Parse the config - should not crash
                config = parse_config_file(temp_path)

                # Verify it parsed successfully
                self.assertEqual(config.crowdsec_config.lapi_key, "test_api_key")
                self.assertEqual(
                    config.crowdsec_config.lapi_url, "http://crowdsec:8080/"
                )

                # Verify warnings were printed
                stderr_output = captured_stderr.getvalue()
                self.assertIn("old_crowdsec_param", stderr_output)
                self.assertIn("deprecated_crowdsec_setting", stderr_output)
                self.assertIn("Warning:", stderr_output)
                self.assertIn("crowdsec_config", stderr_output)

            finally:
                # Clean up
                temp_path.unlink()

        finally:
            # Restore stderr
            sys.stderr = original_stderr

    def test_acl_fast_creation_default_false(self):
        """Test that acl_fast_creation defaults to False when not specified"""
        config_data = {
            "log_level": "info",
            "log_mode": "stdout",
            "log_file": "/tmp/test.log",
            "update_frequency": 10,
            "cache_path": "/tmp/cache.json",
            "crowdsec_config": {
                "lapi_key": "test_key",
                "lapi_url": "http://localhost:8080/",
            },
            "fastly_account_configs": [],
        }

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = parse_config_file(temp_path)
            self.assertFalse(config.acl_fast_creation)
        finally:
            temp_path.unlink()

    def test_acl_fast_creation_true(self):
        """Test that acl_fast_creation is set to True when specified"""
        config_data = {
            "log_level": "info",
            "log_mode": "stdout",
            "log_file": "/tmp/test.log",
            "update_frequency": 10,
            "cache_path": "/tmp/cache.json",
            "acl_fast_creation": True,
            "crowdsec_config": {
                "lapi_key": "test_key",
                "lapi_url": "http://localhost:8080/",
            },
            "fastly_account_configs": [],
        }

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = parse_config_file(temp_path)
            self.assertTrue(config.acl_fast_creation)
        finally:
            temp_path.unlink()

    def test_acl_fast_creation_false(self):
        """Test that acl_fast_creation is set to False when explicitly specified"""
        config_data = {
            "log_level": "info",
            "log_mode": "stdout",
            "log_file": "/tmp/test.log",
            "update_frequency": 10,
            "cache_path": "/tmp/cache.json",
            "acl_fast_creation": False,
            "crowdsec_config": {
                "lapi_key": "test_key",
                "lapi_url": "http://localhost:8080/",
            },
            "fastly_account_configs": [],
        }

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = parse_config_file(temp_path)
            self.assertFalse(config.acl_fast_creation)
        finally:
            temp_path.unlink()
