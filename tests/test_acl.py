from unittest import TestCase
from unittest.mock import MagicMock

from fastly_bouncer.fastly_api import ACL
from fastly_bouncer.service import ACLCollection


def create_acl(name):
    return ACL(id="1", name=name, service_id="a", version="1")


class TestACLCollection(TestCase):
    def test_condition_generator(self):
        acl_collection = ACLCollection(1, MagicMock(), "servie_id", "3")
        acl_collection.acls = [
            create_acl("acl_1"),
            create_acl("acl_2"),
            create_acl("acl_3"),
        ]
        assert (
            acl_collection.generate_conditions()
            == "(client.ip ~ acl_1) || (client.ip ~ acl_2) || (client.ip ~ acl_3)"
        )

        acl_collection.acls = [create_acl("acl_1")]

        assert acl_collection.generate_conditions() == "(client.ip ~ acl_1)"
