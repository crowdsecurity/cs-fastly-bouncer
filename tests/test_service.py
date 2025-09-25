from unittest import TestCase
from unittest.mock import MagicMock

from fastly_bouncer.fastly_api import ACL, FastlyAPI
from fastly_bouncer.service import ACLCollection, Service


def create_acl(name):
    return ACL(id="1", name=name, service_id="a", version="1")


class TestACLCollection(TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.mock_api = MagicMock(spec=FastlyAPI)
        self.mock_api._token = "test_token"

    def test_init(self):
        """Test ACLCollection initialization"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            max_items=5000,
        )

        self.assertEqual(collection.service_id, "service123")
        self.assertEqual(collection.version, "1")
        self.assertEqual(collection.action, "ban")
        self.assertEqual(collection.max_items, 5000)
        self.assertEqual(len(collection.acls), 0)
        self.assertEqual(len(collection.state), 0)

    def test_as_jsonable_dict(self):
        """Test ACLCollection serialization"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            max_items=1000,
            state={"1.2.3.4/32", "5.6.7.8/32"},
        )

        result = collection.as_jsonable_dict()

        self.assertEqual(result["service_id"], "service123")
        self.assertEqual(result["version"], "1")
        self.assertEqual(result["action"], "ban")
        self.assertEqual(result["max_items"], 1000)
        self.assertEqual(result["token"], "test_token")
        self.assertEqual(set(result["state"]), {"1.2.3.4/32", "5.6.7.8/32"})

    def test_condition_generator(self):
        """Test condition generation for multiple ACLs"""
        acl_collection = ACLCollection(self.mock_api, "service_id", "3", "ban")
        acl_collection.acls = [
            create_acl("acl_1"),
            create_acl("acl_2"),
            create_acl("acl_3"),
        ]

        result = acl_collection.generate_conditions()
        expected = "(client.ip ~ acl_1) || (client.ip ~ acl_2) || (client.ip ~ acl_3)"
        self.assertEqual(result, expected)

    def test_condition_generator_single_acl(self):
        """Test condition generation for single ACL"""
        acl_collection = ACLCollection(self.mock_api, "service_id", "3", "ban")
        acl_collection.acls = [create_acl("acl_1")]

        result = acl_collection.generate_conditions()
        self.assertEqual(result, "(client.ip ~ acl_1)")

    def test_insert_item_success(self):
        """Test successful item insertion"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            max_items=5,
        )

        # Add a mock ACL that's not full
        mock_acl = MagicMock()
        mock_acl.is_full.return_value = False
        mock_acl.entries_to_add = set()
        mock_acl.entry_count = 0
        collection.acls = [mock_acl]

        result = collection.insert_item("1.2.3.4/32")

        self.assertTrue(result)
        self.assertIn("1.2.3.4/32", collection.state)
        self.assertIn("1.2.3.4/32", mock_acl.entries_to_add)
        self.assertEqual(mock_acl.entry_count, 1)

    def test_insert_item_max_items_reached(self):
        """Test item insertion when max_items limit is reached"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            max_items=2,
            state={"1.2.3.4/32", "5.6.7.8/32"},  # Already at max
        )

        result = collection.insert_item("9.10.11.12/32")

        self.assertFalse(result)
        self.assertNotIn("9.10.11.12/32", collection.state)

    def test_insert_item_acl_full(self):
        """Test item insertion when all ACLs are full"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            max_items=100,
        )

        # Add a mock ACL that's full
        mock_acl = MagicMock()
        mock_acl.is_full.return_value = True
        collection.acls = [mock_acl]

        result = collection.insert_item("1.2.3.4/32")

        self.assertFalse(result)
        self.assertNotIn("1.2.3.4/32", collection.state)

    def test_remove_item_success(self):
        """Test successful item removal"""
        collection = ACLCollection(
            api=self.mock_api,
            service_id="service123",
            version="1",
            action="ban",
            state={"1.2.3.4/32"},
        )

        # Add a mock ACL that contains the item
        mock_acl = MagicMock()
        mock_acl.entries = {"1.2.3.4/32": "entry_id_123"}
        mock_acl.entries_to_delete = set()
        mock_acl.entry_count = 1
        collection.acls = [mock_acl]

        result = collection.remove_item("1.2.3.4/32")

        self.assertTrue(result)
        self.assertNotIn("1.2.3.4/32", collection.state)
        self.assertIn("1.2.3.4/32", mock_acl.entries_to_delete)
        self.assertEqual(mock_acl.entry_count, 0)

    def test_remove_item_not_found(self):
        """Test item removal when item doesn't exist"""
        collection = ACLCollection(
            api=self.mock_api, service_id="service123", version="1", action="ban"
        )

        # Add a mock ACL that doesn't contain the item
        mock_acl = MagicMock()
        mock_acl.entries = {}
        collection.acls = [mock_acl]

        result = collection.remove_item("1.2.3.4/32")

        self.assertFalse(result)


class TestService(TestCase):
    def setUp(self):
        """Set up test fixtures"""
        self.mock_api = MagicMock(spec=FastlyAPI)
        self.mock_api._token = "test_token"

    def test_service_init(self):
        """Test Service initialization"""
        service = Service(
            api=self.mock_api,
            version="2",
            service_id="service123",
            recaptcha_site_key="site_key_123",
            recaptcha_secret="secret_123",
            activate=True,
        )

        self.assertEqual(service.api, self.mock_api)
        self.assertEqual(service.version, "2")
        self.assertEqual(service.service_id, "service123")
        self.assertEqual(service.recaptcha_site_key, "site_key_123")
        self.assertEqual(service.recaptcha_secret, "secret_123")
        self.assertTrue(service.activate)
        self.assertEqual(service.captcha_expiry_duration, "1800")  # Default
        self.assertTrue(service._first_time)  # Default

    def test_service_post_init_default_actions(self):
        """Test Service __post_init__ sets default supported actions"""
        service = Service(
            api=self.mock_api,
            version="2",
            service_id="service123",
            recaptcha_site_key="site_key_123",
            recaptcha_secret="secret_123",
            activate=True,
        )

        # __post_init__ should set default actions
        self.assertEqual(service.supported_actions, ["ban", "captcha"])
        self.assertIn("ban", service.countries_by_action)
        self.assertIn("captcha", service.countries_by_action)
        self.assertIn("ban", service.autonomoussystems_by_action)
        self.assertIn("captcha", service.autonomoussystems_by_action)

    def test_service_as_jsonable_dict(self):
        """Test Service serialization"""
        service = Service(
            api=self.mock_api,
            version="2",
            service_id="service123",
            recaptcha_site_key="site_key_123",
            recaptcha_secret="secret_123",
            activate=True,
            _first_time=False,
        )

        result = service.as_jsonable_dict()

        self.assertEqual(result["token"], "test_token")
        self.assertEqual(result["version"], "2")
        self.assertEqual(result["service_id"], "service123")
        self.assertEqual(result["recaptcha_site_key"], "site_key_123")
        self.assertEqual(result["recaptcha_secret"], "secret_123")
        self.assertTrue(result["activate"])
        self.assertFalse(result["_first_time"])

    def test_generate_equalto_conditions_for_items_no_quote(self):
        """Test generating equal-to conditions without quotes"""
        items = ["1234", "5678", "9999"]
        result = Service.generate_equalto_conditions_for_items(
            items, "client.as.number"
        )

        expected = "client.as.number == 1234 || client.as.number == 5678 || client.as.number == 9999"
        self.assertEqual(result, expected)

    def test_generate_equalto_conditions_for_items_with_quote(self):
        """Test generating equal-to conditions with quotes"""
        items = ["US", "CA", "FR"]
        result = Service.generate_equalto_conditions_for_items(
            items, "client.geo.country_code", quote=True
        )

        # Items are sorted, so expect alphabetical order
        expected = 'client.geo.country_code == "CA" || client.geo.country_code == "FR" || client.geo.country_code == "US"'
        self.assertEqual(result, expected)

    def test_generate_equalto_conditions_empty_list(self):
        """Test generating conditions with empty list"""
        result = Service.generate_equalto_conditions_for_items([], "client.as.number")
        self.assertEqual(result, "")

    def test_clear_sets(self):
        """Test clearing country and AS sets"""
        service = Service(
            api=self.mock_api,
            version="2",
            service_id="service123",
            recaptcha_site_key="site_key_123",
            recaptcha_secret="secret_123",
            activate=True,
        )

        # Add some data to sets
        service.countries_by_action["ban"].add("US")
        service.autonomoussystems_by_action["captcha"].add("1234")

        service.clear_sets()

        # All sets should be empty
        for action in service.supported_actions:
            self.assertEqual(len(service.countries_by_action[action]), 0)
            self.assertEqual(len(service.autonomoussystems_by_action[action]), 0)

    def test_acl_collection_fast_creation_default(self):
        """Test ACLCollection fast_creation defaults to False"""
        collection = ACLCollection(self.mock_api, "service_id", "3", "ban")
        self.assertFalse(collection.fast_creation)

    def test_acl_collection_fast_creation_true(self):
        """Test ACLCollection fast_creation can be set to True"""
        collection = ACLCollection(
            self.mock_api, "service_id", "3", "ban", fast_creation=True
        )
        self.assertTrue(collection.fast_creation)

    def test_acl_collection_fast_creation_false(self):
        """Test ACLCollection fast_creation can be explicitly set to False"""
        collection = ACLCollection(
            self.mock_api, "service_id", "3", "ban", fast_creation=False
        )
        self.assertFalse(collection.fast_creation)

    def test_acl_collection_serialization_with_fast_creation(self):
        """Test ACLCollection serialization includes fast_creation"""
        collection = ACLCollection(
            self.mock_api, "service_id", "3", "ban", fast_creation=True
        )
        data = collection.as_jsonable_dict()
        self.assertTrue(data["fast_creation"])

        collection_false = ACLCollection(
            self.mock_api, "service_id", "3", "ban", fast_creation=False
        )
        data_false = collection_false.as_jsonable_dict()
        self.assertFalse(data_false["fast_creation"])

    def test_service_reload_acls(self):
        """Test Service reload_acls method exists and has correct structure"""
        # Create a service
        service = Service(
            api=self.mock_api,
            version="3",
            service_id="test_service",
            recaptcha_site_key="test_key",
            recaptcha_secret="test_secret",
            activate=True,
        )

        # Verify the method exists
        self.assertTrue(hasattr(service, "reload_acls"))
        self.assertTrue(callable(getattr(service, "reload_acls")))

        # Verify the helper method exists
        self.assertTrue(hasattr(service, "_refresh_acl_collection"))
        self.assertTrue(callable(getattr(service, "_refresh_acl_collection")))
