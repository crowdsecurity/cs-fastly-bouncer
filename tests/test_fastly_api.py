import unittest
from unittest.mock import MagicMock, patch

from fastly_bouncer.fastly_api import (
    ACL,
    ACL_CAPACITY,
    VCL,
    FastlyAPI,
    log_and_raise_on_error,
)


class TestACLDataClass(unittest.TestCase):
    def test_acl_creation(self):
        """Test ACL dataclass creation and methods"""
        acl = ACL(id="acl123", name="test_acl", service_id="service456", version="1")

        self.assertEqual(acl.id, "acl123")
        self.assertEqual(acl.name, "test_acl")
        self.assertEqual(acl.service_id, "service456")
        self.assertEqual(acl.version, "1")
        self.assertEqual(acl.entry_count, 0)
        self.assertFalse(acl.created)
        self.assertEqual(len(acl.entries_to_add), 0)
        self.assertEqual(len(acl.entries_to_delete), 0)

    def test_acl_is_full(self):
        """Test ACL is_full method"""
        acl = ACL(id="1", name="test", service_id="svc", version="1")

        # Not full initially
        self.assertFalse(acl.is_full())

        # Full when at capacity
        acl.entry_count = ACL_CAPACITY
        self.assertTrue(acl.is_full())

    def test_acl_as_jsonable_dict(self):
        """Test ACL serialization to dict"""
        acl = ACL(
            id="acl123",
            name="test_acl",
            service_id="service456",
            version="1",
            entry_count=5,
            created=True,
        )
        acl.entries_to_add.add("1.2.3.4/32")
        acl.entries_to_delete.add("5.6.7.8/32")
        acl.entries["9.10.11.12/32"] = "entry_id_123"

        result = acl.as_jsonable_dict()

        self.assertEqual(result["id"], "acl123")
        self.assertEqual(result["name"], "test_acl")
        self.assertEqual(result["entry_count"], 5)
        self.assertTrue(result["created"])
        self.assertIn("1.2.3.4/32", result["entries_to_add"])
        self.assertIn("5.6.7.8/32", result["entries_to_delete"])
        self.assertEqual(result["entries"]["9.10.11.12/32"], "entry_id_123")


class TestVCLDataClass(unittest.TestCase):
    def test_vcl_creation(self):
        """Test VCL dataclass creation"""
        vcl = VCL(
            name="test_vcl",
            service_id="service123",
            version="1",
            action='error 403 "Forbidden";',
        )

        self.assertEqual(vcl.name, "test_vcl")
        self.assertEqual(vcl.service_id, "service123")
        self.assertEqual(vcl.version, "1")
        self.assertEqual(vcl.action, 'error 403 "Forbidden";')
        self.assertEqual(vcl.type, "recv")  # Default
        self.assertEqual(vcl.dynamic, "1")  # Default
        self.assertEqual(vcl.conditional, "")  # Default

    def test_vcl_to_dict_with_conditional(self):
        """Test VCL to_dict method with conditional"""
        vcl = VCL(
            name="test_vcl",
            service_id="service123",
            version="1",
            action='error 403 "Forbidden";',
            conditional="if (client.ip ~ bad_ips)",
        )

        result = vcl.to_dict()

        expected_content = 'if (client.ip ~ bad_ips) { error 403 "Forbidden"; }'
        self.assertEqual(result["content"], expected_content)
        self.assertEqual(result["name"], "test_vcl")
        self.assertEqual(result["type"], "recv")

    def test_vcl_to_dict_without_conditional(self):
        """Test VCL to_dict method without conditional"""
        vcl = VCL(
            name="test_vcl",
            service_id="service123",
            version="1",
            action='error 403 "Forbidden";',
        )

        result = vcl.to_dict()

        self.assertEqual(result["content"], 'error 403 "Forbidden";')
        self.assertEqual(result["name"], "test_vcl")

    def test_vcl_as_jsonable_dict(self):
        """Test VCL serialization via asdict"""
        vcl = VCL(
            name="test_vcl",
            service_id="service123",
            version="1",
            action="test_action",
            type="deliver",
        )

        result = vcl.as_jsonable_dict()

        # Should return result of asdict()
        self.assertEqual(result["name"], "test_vcl")
        self.assertEqual(result["type"], "deliver")


class TestLogAndRaiseOnError(unittest.IsolatedAsyncioTestCase):
    @patch("fastly_bouncer.fastly_api.logger")
    async def test_log_and_raise_on_error_success(self, mock_logger):
        """Test log_and_raise_on_error with successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Should not raise or log for success
        await log_and_raise_on_error(mock_response)

        mock_logger.error.assert_not_called()
        mock_response.raise_for_status.assert_not_called()

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_log_and_raise_on_error_client_error(self, mock_logger):
        """Test log_and_raise_on_error with 4xx error"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.request.method = "GET"
        mock_response.url = "https://api.fastly.com/service/123"

        await log_and_raise_on_error(mock_response)

        mock_logger.error.assert_called_once()
        mock_response.raise_for_status.assert_called_once()

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_log_and_raise_on_error_exception_handling(self, mock_logger):
        """Test log_and_raise_on_error when response.text raises exception"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text.side_effect = Exception("Error getting text")
        mock_response.request.method = "POST"
        mock_response.url = "https://api.fastly.com/service/456"

        await log_and_raise_on_error(mock_response)

        # Should log generic error message
        mock_logger.error.assert_called_once()
        self.assertIn("HTTP 500 error", mock_logger.error.call_args[0][0])
        mock_response.raise_for_status.assert_called_once()


class TestFastlyAPI(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.api = FastlyAPI("test_token_123")

    def test_init(self):
        """Test FastlyAPI initialization"""
        self.assertEqual(self.api._token, "test_token_123")
        self.assertEqual(self.api._acl_count, 0)
        self.assertIsNotNone(self.api.session)

    def test_api_url_static_method(self):
        """Test api_url static method"""
        result = FastlyAPI.api_url("/service/123")
        self.assertEqual(result, "https://api.fastly.com/service/123")

        result = FastlyAPI.api_url("/service/456/version")
        self.assertEqual(result, "https://api.fastly.com/service/456/version")

    @patch.object(FastlyAPI, "get_all_acls")
    @patch.object(FastlyAPI, "get_all_vcls")
    async def test_clear_crowdsec_resources_none_found(
        self, mock_get_vcls, mock_get_acls
    ):
        """Test clear_crowdsec_resources when no CrowdSec resources exist"""
        # Mock no CrowdSec resources
        other_acl = ACL(id="acl1", name="other_acl", service_id="svc", version="1")
        other_vcl = VCL(name="other_rule", service_id="svc", version="1", action="test")

        mock_get_acls.return_value = [other_acl]
        mock_get_vcls.return_value = [other_vcl]

        # Should return early without attempting deletions
        result = await self.api.clear_crowdsec_resources("service123", "1")

        self.assertIsNone(result)

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_get_candidate_version_active_found(self, mock_logger):
        """Test get_candidate_version when active version exists"""
        # Mock response with active version
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"number": 1, "active": False, "updated_at": "2023-01-01T10:00:00Z"},
            {"number": 2, "active": True, "updated_at": "2023-01-02T10:00:00Z"},
            {"number": 3, "active": False, "updated_at": "2023-01-03T10:00:00Z"},
        ]

        with patch.object(self.api.session, "get", return_value=mock_response):
            result = await self.api.get_candidate_version("service123")

        self.assertEqual(result, "2")
        mock_logger.info.assert_called_with("Found active version: 2 ")

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_get_candidate_version_no_active_uses_latest_updated(
        self, mock_logger
    ):
        """Test get_candidate_version falls back to most recently updated version"""
        # Mock response with no active versions
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"number": 1, "active": False, "updated_at": "2023-01-01T10:00:00Z"},
            {
                "number": 3,
                "active": False,
                "updated_at": "2023-01-03T15:30:00Z",  # Most recent
            },
            {"number": 2, "active": False, "updated_at": "2023-01-02T10:00:00Z"},
        ]

        with patch.object(self.api.session, "get", return_value=mock_response):
            result = await self.api.get_candidate_version("service123")

        self.assertEqual(result, "3")
        mock_logger.info.assert_called_with("Using last updated version: 3 ")

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_get_candidate_version_single_version(self, mock_logger):
        """Test get_candidate_version with single version"""
        # Mock response with single version (not active)
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"number": 1, "active": False, "updated_at": "2023-01-01T10:00:00Z"}
        ]

        with patch.object(self.api.session, "get", return_value=mock_response):
            result = await self.api.get_candidate_version("service123")

        self.assertEqual(result, "1")
        mock_logger.info.assert_called_with("Using last updated version: 1 ")

    @patch("fastly_bouncer.fastly_api.logger")
    async def test_get_candidate_version_prefers_active_over_newer(self, mock_logger):
        """Test get_candidate_version prefers active version even if newer version exists"""
        # Mock response where active version is older than another version
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "number": 1,
                "active": True,  # Active but older
                "updated_at": "2023-01-01T10:00:00Z",
            },
            {
                "number": 2,
                "active": False,  # Newer but not active
                "updated_at": "2023-01-02T10:00:00Z",
            },
        ]

        with patch.object(self.api.session, "get", return_value=mock_response):
            result = await self.api.get_candidate_version("service123")

        self.assertEqual(result, "1")
        mock_logger.info.assert_called_with("Found active version: 1 ")

    async def test_get_candidate_version_api_call(self):
        """Test get_candidate_version makes correct API call"""
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"number": 1, "active": True, "updated_at": "2023-01-01T10:00:00Z"}
        ]

        with patch.object(
            self.api.session, "get", return_value=mock_response
        ) as mock_get:
            await self.api.get_candidate_version("test_service_id")

        mock_get.assert_called_once_with(
            "https://api.fastly.com/service/test_service_id/version"
        )


if __name__ == "__main__":
    unittest.main()
