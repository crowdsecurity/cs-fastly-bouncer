import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

import trio
from fastly_bouncer import vcl_templates
from fastly_bouncer.fastly_api import ACL, VCL, FastlyAPI
from fastly_bouncer.utils import with_suffix

logger: logging.Logger = logging.getLogger("")


class ACLCollection:
    """
    This is an abstraction of collection of ACLs. It allows us to provision multiple ACLs. It also
    distributes IPs among these ACLs.
    """

    def __init__(
        self,
        api: FastlyAPI,
        service_id: str,
        version: str,
        action: str,
        max_items: int = 20000,
        acls=[],
        state=set(),
        fast_creation: bool = False,
    ):
        self.acls: List[ACL] = acls
        self.api: FastlyAPI = api
        self.service_id = service_id
        self.version = version
        self.action = action
        self.max_items = max_items
        self.state: Set = state
        self.fast_creation = fast_creation

    def as_jsonable_dict(self) -> Dict:
        return {
            "acls": list(map(lambda acl: acl.as_jsonable_dict(), self.acls)),
            "token": self.api._token,
            "service_id": self.service_id,
            "version": self.version,
            "action": self.action,
            "max_items": self.max_items,
            "state": list(self.state),
            "fast_creation": self.fast_creation,
        }

    async def create_acls(self, acl_count: int) -> List[ACL]:
        """
        Provisions ACLs. Uses either fast parallel creation or sequential creation
        based on the fast_creation setting.
        """
        if self.fast_creation:
            return await self._create_acls_fast(acl_count)
        else:
            return await self._create_acls_sequential(acl_count)

    async def _create_single_acl(self, index: int) -> ACL:
        """
        Shared helper method to create a single ACL with consistent naming and logging.
        """
        acl_name = f"crowdsec_{self.action}_{index}"
        logger.debug(
            with_suffix(f"Creating acl {acl_name} ", service_id=self.service_id)
        )
        acl = await self.api.create_acl_for_service(
            service_id=self.service_id, version=self.version, name=acl_name
        )
        logger.info(with_suffix(f"Acl {acl_name} created", service_id=self.service_id))
        return acl

    async def _create_acls_fast(self, acl_count: int) -> List[ACL]:
        """
        Fast ACL creation using trio.start_soon for parallel execution.
        ACL order will be random but creation is faster.
        """
        acls = [None] * acl_count

        async def create_and_store_acl(index: int):
            acl = await self._create_single_acl(index)
            acls[index] = acl

        async with trio.open_nursery() as nursery:
            for i in range(acl_count):
                nursery.start_soon(create_and_store_acl, i)

        return acls

    async def _create_acls_sequential(self, acl_count: int) -> List[ACL]:
        """
        Sequential ACL creation in reverse order so ACL 0 appears first in Fastly UI
        (Fastly sorts by creation date descending, so last created appears first)
        """
        acls = [None] * acl_count  # Pre-allocate list with correct size
        # Create ACLs in reverse order (highest index first, 0 last)
        for i in reversed(range(acl_count)):
            acl = await self._create_single_acl(i)
            acls[i] = acl  # Place ACL at correct index position

            # Small delay to ensure proper ordering at Fastly API level
            # Do not sleep after the last ACL creation (which is ACL 0)
            if i > 0:
                await trio.sleep(0.6)
        return acls

    def insert_item(self, item: str) -> bool:
        """
        Returns True if the item was successfully allocated in an ACL
        """
        # Check if we've reached the configured max_items limit
        total_items = len(self.state)
        if total_items >= self.max_items:
            return False

        # Check if item is already present in some ACL
        for acl in self.acls:
            if not acl.is_full():
                acl.entries_to_add.add(item)
                acl.entry_count += 1
                self.state.add(item)
                return True
        return False

    def remove_item(self, item: str) -> bool:
        """
        Returns True if item is found, and removed.
        """
        for acl in self.acls:
            if item not in acl.entries:
                continue
            acl.entries_to_delete.add(item)
            self.state.discard(item)
            acl.entry_count -= 1
            return True
        return False

    def transform_to_state(self, new_state):
        new_items = new_state - self.state
        expired_items = self.state - new_state

        if new_items:
            logger.info(
                with_suffix(
                    f"Adding {len(new_items)} items to acl collection",
                    service_id=self.service_id,
                    action=self.action,
                )
            )

        if expired_items:
            logger.info(
                with_suffix(
                    f"Removing {len(expired_items)} items from acl collection",
                    service_id=self.service_id,
                    action=self.action,
                )
            )

        if not new_items and not expired_items:
            logger.info(
                with_suffix(
                    "No items to add or remove from acl collection",
                    service_id=self.service_id,
                    action=self.action,
                )
            )

        for new_item in new_items:
            if any([new_item in acl.entries for acl in self.acls]):
                continue

            if not self.insert_item(new_item):
                logger.warning(
                    with_suffix(
                        f"ACL collection for {self.action} has reached configured max_items limit "
                        f"({self.max_items} items). Ignoring remaining items.",
                        service_id=self.service_id,
                    )
                )
                break

        for expired_item in expired_items:
            self.remove_item(expired_item)

    async def commit(self) -> bool:
        acls_to_change = list(
            filter(lambda acl: acl.entries_to_add or acl.entries_to_delete, self.acls)
        )

        if len(acls_to_change):
            # Track success of each ACL update
            results = {}
            async with trio.open_nursery() as n:
                for acl in acls_to_change:
                    n.start_soon(self.update_acl, acl, results)

            # Check if all ACL updates succeeded
            all_successful = all(results.values())
            if all_successful:
                logger.info(
                    with_suffix(
                        f"ACL collection for {self.action} updated successfully",
                        service_id=self.service_id,
                    )
                )
            else:
                logger.warning(
                    with_suffix(
                        f"ACL collection for {self.action} had partial failures",
                        service_id=self.service_id,
                    )
                )
            return all_successful

        return True  # No changes needed, consider successful

    def generate_conditions(self) -> str:
        conditions = []
        for acl in self.acls:
            conditions.append(f"(client.ip ~ {acl.name})")

        return " || ".join(conditions)

    async def update_acl(self, acl: ACL, results: Dict = None):
        logger.debug(
            with_suffix(
                f"Commiting changes to acl {acl.name}",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )
        success = await self.api.process_acl(acl)

        # Store result if results dict provided
        if results is not None:
            results[acl.id] = success

        logger.debug(
            with_suffix(
                f"Commited changes to acl {acl.name} - {'success' if success else 'partial failure'}",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )


@dataclass
class Service:
    api: FastlyAPI
    version: str
    service_id: str
    recaptcha_site_key: str
    recaptcha_secret: str
    activate: bool
    captcha_expiry_duration: str = "1800"
    _first_time: bool = True
    supported_actions: List = field(default_factory=list)
    vcl_by_action: Dict[str, VCL] = field(default_factory=dict)
    static_vcls: List[VCL] = field(default_factory=list)
    current_conditional_by_action: Dict[str, str] = field(default_factory=dict)
    countries_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    autonomoussystems_by_action: Dict[str, Set[str]] = field(default_factory=dict)
    acl_collection_by_action: Dict[str, ACLCollection] = field(default_factory=dict)

    @classmethod
    def from_jsonable_dict(cls, jsonable_dict: Dict):
        api = FastlyAPI(jsonable_dict["token"])
        vcl_by_action = {
            action: VCL(**data)
            for action, data in jsonable_dict["vcl_by_action"].items()
        }
        static_vcls = [VCL(**data) for data in jsonable_dict["static_vcls"]]
        acl_collection_by_action = {
            action: ACLCollection(
                api,
                service_id=jsonable_dict["service_id"],
                version=jsonable_dict["version"],
                action=action,
                max_items=data.get(
                    "max_items", 20000
                ),  # Use cached max_items or default
                state=set(data["state"]),
                acls=[
                    ACL(
                        id=acl_data["id"],
                        name=acl_data["name"],
                        service_id=acl_data["service_id"],
                        version=acl_data["version"],
                        entries_to_add=set(acl_data["entries_to_add"]),
                        entries_to_delete=set(acl_data["entries_to_delete"]),
                        entries=acl_data["entries"],
                        entry_count=acl_data["entry_count"],
                        created=acl_data["created"],
                    )
                    for acl_data in data["acls"]
                ],
                fast_creation=data.get("fast_creation", False),
            )
            for action, data in jsonable_dict["acl_collection_by_action"].items()
        }
        countries_by_action = {
            action: set(countries)
            for action, countries in jsonable_dict["countries_by_action"].items()
        }
        autonomoussystems_by_action = {
            action: set(systems)
            for action, systems in jsonable_dict["autonomoussystems_by_action"].items()
        }

        return cls(
            api=api,
            version=jsonable_dict["version"],
            service_id=jsonable_dict["service_id"],
            recaptcha_site_key=jsonable_dict["recaptcha_site_key"],
            recaptcha_secret=jsonable_dict["recaptcha_secret"],
            activate=jsonable_dict["activate"],
            _first_time=jsonable_dict["_first_time"],
            supported_actions=jsonable_dict["supported_actions"],
            vcl_by_action=vcl_by_action,
            static_vcls=static_vcls,
            current_conditional_by_action=jsonable_dict[
                "current_conditional_by_action"
            ],
            countries_by_action=countries_by_action,
            autonomoussystems_by_action=autonomoussystems_by_action,
            acl_collection_by_action=acl_collection_by_action,
        )

    def as_jsonable_dict(self):
        """
        This returns a dict which is be json serializable
        """
        vcl_by_action = {
            action: vcl.as_jsonable_dict() for action, vcl in self.vcl_by_action.items()
        }
        acl_collection_by_action = {
            action: acl_collection.as_jsonable_dict()
            for action, acl_collection in self.acl_collection_by_action.items()
        }
        countries_by_action = {
            action: list(countries)
            for action, countries in self.countries_by_action.items()
        }
        autonomoussystems_by_action = {
            action: list(systems)
            for action, systems in self.autonomoussystems_by_action.items()
        }
        static_vcls = list(map(lambda vcl: vcl.as_jsonable_dict(), self.static_vcls))

        return {
            "token": self.api._token,
            "version": self.version,
            "service_id": self.service_id,
            "recaptcha_site_key": self.recaptcha_site_key,
            "recaptcha_secret": self.recaptcha_secret,
            "activate": self.activate,
            "_first_time": self._first_time,
            "supported_actions": self.supported_actions,
            "vcl_by_action": vcl_by_action,
            "static_vcls": static_vcls,
            "current_conditional_by_action": self.current_conditional_by_action,
            "countries_by_action": countries_by_action,
            "autonomoussystems_by_action": autonomoussystems_by_action,
            "acl_collection_by_action": acl_collection_by_action,
        }

    def __post_init__(self):
        if not self.supported_actions:
            self.supported_actions = ["ban", "captcha"]

        self.countries_by_action = {action: set() for action in self.supported_actions}
        self.autonomoussystems_by_action = {
            action: set() for action in self.supported_actions
        }
        jwt_secret = str(uuid.uuid1())
        if not self.vcl_by_action:
            self.vcl_by_action = {
                "ban": VCL(
                    name="crowdsec_ban_rule",
                    service_id=self.service_id,
                    action='error 403 "Forbidden";',
                    version=self.version,
                ),
                "captcha": VCL(
                    name="crowdsec_captcha_rule",
                    service_id=self.service_id,
                    version=self.version,
                    action=vcl_templates.CAPTCHA_RECV_VCL.format(
                        RECAPTCHA_SECRET=self.recaptcha_secret,
                        JWT_SECRET=jwt_secret,
                    ),
                ),
            }
            for action in [
                action
                for action in self.vcl_by_action
                if action not in self.supported_actions
            ]:
                del self.vcl_by_action[action]

        if not self.static_vcls and "captcha" in self.supported_actions:
            self.static_vcls = [
                VCL(
                    name="crowdsec_captcha_renderer",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_RENDER_VCL.format(
                        RECAPTCHA_SITE_KEY=self.recaptcha_site_key
                    ),
                    version=self.version,
                    type="error",
                ),
                VCL(
                    name="crowdsec_captcha_validator",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_VALIDATOR_VCL.format(
                        JWT_SECRET=jwt_secret,
                        COOKIE_EXPIRY_DURATION=self.captcha_expiry_duration,
                    ),
                    version=self.version,
                    type="deliver",
                ),
                VCL(
                    name="crowdsec_captcha_google_backend",
                    service_id=self.service_id,
                    action=vcl_templates.GOOGLE_BACKEND.format(
                        SERVICE_ID=self.service_id
                    ),
                    version=self.version,
                    type="init",
                ),
            ]

    async def create_static_vcls(self):
        async with trio.open_nursery() as n:
            for vcl in self.static_vcls:
                n.start_soon(self.api.create_vcl, vcl)

    def clear_sets(self):
        for action in self.supported_actions:
            self.countries_by_action[action].clear()
            self.autonomoussystems_by_action[action].clear()

    async def transform_state(self, new_state: Dict[str, str]) -> bool:
        """
        This method transforms the configuration of the service according to the "new_state".
        "new_state" is mapping of item->action. Eg  {"1.2.3.4": "ban", "CN": "captcha", "1234": "ban"}.
        item is string representation of IP or Country or AS Number.
        """
        # Log old state count
        old_state_count = sum(
            len(acl_collection.state)
            for acl_collection in self.acl_collection_by_action.values()
        )
        logger.info(
            with_suffix(
                f"Old state contains {old_state_count} decisions",
                service_id=self.service_id,
            )
        )

        new_acl_state_by_action = {action: set() for action in self.supported_actions}

        prev_countries_by_action = {
            action: countries.copy()
            for action, countries in self.countries_by_action.items()
        }
        prev_autonomoussystems_by_action = {
            action: systems.copy()
            for action, systems in self.autonomoussystems_by_action.items()
        }

        self.clear_sets()

        for item, action in new_state.items():
            if action not in self.supported_actions:
                continue

            # hacky check to see it's not IP
            if "." not in item and ":" not in item:
                # It's a AS number
                if item.isnumeric():
                    self.autonomoussystems_by_action[action].add(item)

                # It's a country.
                elif len(item) == 2:
                    self.countries_by_action[action].add(item)

            # It's an IP
            else:
                new_acl_state_by_action[action].add(item)

        for action, expected_acl_state in new_acl_state_by_action.items():
            self.acl_collection_by_action[action].transform_to_state(expected_acl_state)

        for action in self.supported_actions:
            expired_countries = (
                prev_countries_by_action[action] - self.countries_by_action[action]
            )
            if expired_countries:
                logger.info(f"{action} removed for countries {expired_countries} ")

            expired_systems = (
                prev_autonomoussystems_by_action[action]
                - self.autonomoussystems_by_action[action]
            )
            if expired_systems:
                logger.info(f"{action} removed for AS {expired_systems} ")

            new_countries = (
                self.countries_by_action[action] - prev_countries_by_action[action]
            )
            if new_countries:
                logger.info(f"Countries {new_countries} will get {action} ")

            new_systems = (
                self.autonomoussystems_by_action[action]
                - prev_autonomoussystems_by_action[action]
            )
            if new_systems:
                logger.info(f"AS {new_systems} will get {action}")

        success = await self.commit()
        return success

    async def commit(self) -> bool:
        # Track success of ACL collection updates
        acl_results = {}
        async with trio.open_nursery() as n:
            for action in self.vcl_by_action:
                n.start_soon(self._commit_acl_collection, action, acl_results)
                n.start_soon(self.update_vcl, action)

        # Check if all ACL collections updated successfully
        all_acl_successful = all(acl_results.values()) if acl_results else True

        if self._first_time and self.activate:
            try:
                logger.debug(
                    with_suffix(
                        f"Activating new service version {self.version}",
                        service_id=self.service_id,
                    )
                )
                await self.api.activate_service_version(self.service_id, self.version)
                logger.info(
                    with_suffix(
                        f"New service version {self.version} activated",
                        service_id=self.service_id,
                    )
                )
                self._first_time = False
                return all_acl_successful  # Return ACL success status
            except Exception as e:
                logger.error(
                    with_suffix(
                        f"Failed to activate service version {self.version}: {e}",
                        service_id=self.service_id,
                    )
                )
                return False  # Activation failed

        return all_acl_successful

    async def _commit_acl_collection(self, action: str, results: Dict):
        """Helper method to commit an ACL collection and track its success."""
        success = await self.acl_collection_by_action[action].commit()
        results[action] = success

    async def update_vcl(self, action: str):
        vcl = self.vcl_by_action[action]
        new_conditional = self.generate_conditional_for_action(action)
        if new_conditional != vcl.conditional:
            vcl.conditional = new_conditional
            vcl = await self.api.create_or_update_vcl(vcl)
            self.vcl_by_action[action] = vcl

    @staticmethod
    def generate_equalto_conditions_for_items(
        items: Iterable, equal_to: str, quote=False
    ):
        items = sorted(items)
        if not quote:
            return " || ".join([f"{equal_to} == {item}" for item in items])
        return " || ".join([f'{equal_to} == "{item}"' for item in items])

    def generate_conditional_for_action(self, action):
        acl_conditions = self.acl_collection_by_action[action].generate_conditions()
        country_conditions = self.generate_equalto_conditions_for_items(
            self.countries_by_action[action], "client.geo.country_code", quote=True
        )
        as_conditions = self.generate_equalto_conditions_for_items(
            self.autonomoussystems_by_action[action], "client.as.number"
        )

        condition = " || ".join(
            [
                condition
                for condition in [acl_conditions, country_conditions, as_conditions]
                if condition
            ]
        )
        return f"if ( {condition} )"

    async def reload_acls(self):
        """Refresh all ACL entries from Fastly to synchronize local state."""
        logger.info(
            with_suffix(
                "Refreshing ACL entries from Fastly",
                service_id=self.service_id,
            )
        )

        async with trio.open_nursery() as n:
            for action, acl_collection in self.acl_collection_by_action.items():
                n.start_soon(self._refresh_acl_collection, action, acl_collection)

        # Update VCL conditionals to match current ACL state after refresh
        for action in self.vcl_by_action:
            vcl = self.vcl_by_action[action]
            vcl.conditional = self.generate_conditional_for_action(action)

    async def _refresh_acl_collection(self, action: str, acl_collection):
        """Refresh an entire ACL collection and synchronize local state."""
        try:
            # First refresh all ACL entries from Fastly
            async with trio.open_nursery() as n:
                for acl in acl_collection.acls:
                    n.start_soon(self.api.refresh_acl_entries, acl)

            # Now rebuild the local state from what's actually in Fastly
            new_state = set()
            for acl in acl_collection.acls:
                # Add all IP entries from Fastly to our local state
                for ip_with_subnet in acl.entries.keys():
                    new_state.add(ip_with_subnet)

            # Update the collection's state to match Fastly
            acl_collection.state = new_state

            # Clear any pending operations since we're now in sync
            for acl in acl_collection.acls:
                acl.entries_to_add.clear()
                acl.entries_to_delete.clear()

            logger.debug(
                with_suffix(
                    f"Refreshed ACL collection with {len(new_state)} entries",
                    action=action,
                    service_id=self.service_id,
                )
            )
        except Exception as e:
            logger.error(
                with_suffix(
                    f"Failed to refresh ACL collection for {action}: {e}",
                    service_id=self.service_id,
                )
            )
