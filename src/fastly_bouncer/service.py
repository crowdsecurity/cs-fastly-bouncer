import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Set

import trio
from httpx import HTTPError
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_result

from fastly_bouncer import vcl_templates
from fastly_bouncer.fastly_api import ACL, VCL, FastlyAPI
from fastly_bouncer.utils import with_suffix, transient_http_error

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
        acls=[],
        state=set(),
    ):
        self.acls: List[ACL] = acls
        self.api: FastlyAPI = api
        self.service_id = service_id  # Fastly service ID
        self.version = version # Fastly version ID, probably of first time it was added and doesn't change
        self.action = action  # "ban" "captcha" etc
        self.state: Set = state  # All the "ip/subnet" for the ACLCollection

    def as_jsonable_dict(self) -> Dict:
        return {
            "acls": list(map(lambda acl: acl.as_jsonable_dict(), self.acls)),
            "token": self.api._token,
            "service_id": self.service_id,
            "version": self.version,
            "action": self.action,
            "state": list(self.state),
        }

    async def create_acl(self, i, sender_chan):
        acl_name = f"crowdsec_{self.action}_{i}"
        logger.info(with_suffix(f"creating acl {acl_name} ", service_id=self.service_id))
        acl = await self.api.create_acl_for_service(
            service_id=self.service_id, version=self.version, name=acl_name
        )
        logger.info(with_suffix(f"created acl {acl_name}", service_id=self.service_id))
        async with sender_chan:
            await sender_chan.send(acl)

    async def create_acls(self, acl_count: int) -> None:
        """
        Provisions ACLs
        """
        acls = []
        sender, receiver = trio.open_memory_channel(0)
        async with trio.open_nursery() as n:
            async with sender:
                for i in range(acl_count):
                    n.start_soon(self.create_acl, i, sender.clone())

            async with receiver:
                async for acl in receiver:
                    acls.append(acl)
        return acls

    def stage_insert_item(self, item: str) -> bool:
        """
        Returns True if the item was staged in an ACL, False if all the ACLs are full.
        """
        # Check if item is already present in some ACL
        for acl in self.acls:
            if not acl.is_full():
                acl.entries_to_add.add(item)
                acl.entry_count += 1
                return True
        return False

    def stage_remove_item(self, item: str) -> bool:
        """
        Returns True if item is found, and staged for removal.
        """
        for acl in self.acls:
            if item not in acl.entries:
                continue
            acl.entries_to_delete.add(item)
            acl.entry_count -= 1
            return True
        return False

    def transform_to_state(self, new_state):
        """Stages change alter `self` to be in `new_state` but does not send to fastly or change `self.state`."""
        new_items = new_state - self.state
        expired_items = self.state - new_state
        if new_items:
            logger.info(
                with_suffix(
                    f"adding {len(new_items)} items to acl collection",
                    service_id=self.service_id,
                    action=self.action,
                )
            )

        if expired_items:
            logger.info(
                with_suffix(
                    f"removing {len(expired_items)} items from acl collection",
                    service_id=self.service_id,
                    action=self.action,
                )
            )

        for new_item in new_items:
            if any([new_item in acl.entries for acl in self.acls]):
                continue

            if not self.stage_insert_item(new_item):
                logger.error(
                    with_suffix(
                        f"acl_collection for {self.action} is full. Ignoring remaining items.",
                        service_id=self.service_id,
                    )
                )
                break

        for expired_item in expired_items:
            if not self.stage_remove_item(expired_item):
                logger.debug(with_suffix(f"{expired_item} not found in acl_collection. Ignoring.",
                        service_id=self.service_id))

        # at this point changes are staged in the ACLs but not yet sent to Fastly or changed in `ACLCollection.state`

    async def commit(self) -> None:
        """Make changes go live.
        Send the changes stored in `self.acls.entries_to_add` and `self.acls.entries_to_delete` to Fastly and
        update `self.state`."""
        acls_to_change = list(filter(lambda acl: acl.entries_to_add or acl.entries_to_delete, self.acls))

        if len(acls_to_change):
            async with trio.open_nursery() as n:
                for acl in acls_to_change:
                    n.start_soon(self.commit_acl, acl)
            logger.info(
                with_suffix(
                    f"acl collection for {self.action} updated",
                    service_id=self.service_id,
                )
            )

            try:
                await self.refresh_from_fastly(acls_to_change)
            except HTTPError as exc:
                logger.warning(f"Could not refresh ACL {acl.name} with {exc.request.url} - {exc}")

    def generate_conditions(self) -> str:
        conditions = []
        for acl in self.acls:
            conditions.append(f"(client.ip ~ {acl.name})")

        return " || ".join(conditions)


    @retry(wait=wait_exponential(multiplier=1, min=2, max=10),
           stop=stop_after_attempt(10),
           retry=retry_if_result(transient_http_error))
    async def _commit_acl_diff(self, acl: ACL):
        logger.debug(
            with_suffix(
                f"commiting changes to acl {acl.name} to fastly",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )
        await self.api.process_acl(acl)

        self.state.difference_update(acl.entries_to_delete)
        self.state.update(acl.entries_to_add)
        acl.entries_to_add = set()
        acl.entries_to_delete = set()
        logger.debug(
            with_suffix(
                f"finished commiting changes to acl {acl.name} to fastly, state updated",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )

    @retry(wait=wait_exponential(multiplier=1, min=2, max=10),
           stop=stop_after_attempt(10),
           retry=retry_if_result(transient_http_error))
    async def _refresh_then_commit(self, acl: ACL):
        logger.debug(
            with_suffix(
                f"refreshing acl {acl.name} from fastly",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )
        await self.api.refresh_acl_entries(acl)
        current = acl.as_set()

        # if we have an add, and it exists at Fastly, we don't want to add it again at fastly,
        # but we still need to put it in self.state.
        state_add = acl.entries_to_add.copy()
        acl.entries_to_add.difference_update(current)

        # if we have a delete, and it doesn't exist at Fastly, don't want to add it again or Fasty will 400
        # but we still need to remove it from self.state
        state_delete = acl.entries_to_delete.copy()
        acl.entries_to_delete = current & acl.entries_to_delete

        logger.info(with_suffix(f"{acl.name} local state refreshed, out of sync repaired",
                                service_id=self.service_id))

        logger.debug(
            with_suffix(
                f"commiting changes to acl {acl.name} to fastly",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )
        await self.api.process_acl(acl)

        self.state.difference_update(state_delete)
        self.state.update(state_add)
        acl.entries_to_add = set()
        acl.entries_to_delete = set()

        logger.debug(
            with_suffix(
                f"finished refresh of acl {acl.name} and changes sent to fastly",
                service_id=self.service_id,
                acl_collection=self.action,
            )
        )

    async def commit_acl(self, acl: ACL):
        """Sends changes to Fastly and updates `self.state` for this single `acl`."""
        try:
            await self._commit_acl_diff(acl)
        except* HTTPError as exc:
            httpexc = exc.split(HTTPError)[0].exceptions[0]
            if httpexc.response.status_code == 400:
                logger.info(with_suffix(f"{acl.name} local state out of sync with fastly,"
                                        f"msg: '{httpexc.response.text}'", service_id=self.service_id))
                await self._refresh_then_commit(acl)
            else:
                raise exc


    async def refresh_from_fastly(self, acls: List[ACL]=[]) -> None:
        """Get data for ACLs from fastly and rebuild state."""
        if not acls:
            acls_to_refresh = self.acls
        else:
            acls_to_refresh = acls

        async with trio.open_nursery() as n:
            for acl in acls_to_refresh:
                n.start_soon(self.api.refresh_acl_entries, acl)

        self.state = set().union(*[acl.as_set() for acl in acls_to_refresh])


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
    supported_actions: List = field(default_factory=list)  # Ex ["ban", "captcha"] Action types from Crowdsec policies.
    vcl_by_action: Dict[str, VCL] = field(default_factory=dict)
    static_vcls: List[VCL] = field(default_factory=list)  # BDC Not in use, related to recaptcha
    current_conditional_by_action: Dict[str, str] = field(default_factory=dict)  # BDC Not in use
    countries_by_action: Dict[str, Set[str]] = field(default_factory=dict)  # BDC Not in use
    autonomoussystems_by_action: Dict[str, Set[str]] = field(default_factory=dict)  # BDC Not in use
    acl_collection_by_action: Dict[str, ACLCollection] = field(default_factory=dict)

    @classmethod
    def from_jsonable_dict(cls, jsonable_dict: Dict):
        api = FastlyAPI(jsonable_dict["token"])
        vcl_by_action = {
            action: VCL(**data) for action, data in jsonable_dict["vcl_by_action"].items()
        }
        static_vcls = [VCL(**data) for data in jsonable_dict["static_vcls"]]
        acl_collection_by_action = {
            action: ACLCollection(
                api,
                service_id=jsonable_dict["service_id"],
                version=jsonable_dict["version"],
                action=action,
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
            current_conditional_by_action=jsonable_dict["current_conditional_by_action"],
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
            action: list(countries) for action, countries in self.countries_by_action.items()
        }
        autonomoussystems_by_action = {
            action: list(systems) for action, systems in self.autonomoussystems_by_action.items()
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
        self.autonomoussystems_by_action = {action: set() for action in self.supported_actions}
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
                action for action in self.vcl_by_action if action not in self.supported_actions
            ]:
                del self.vcl_by_action[action]

        if not self.static_vcls and "captcha" in self.supported_actions:
            self.static_vcls = [
                VCL(
                    name=f"crowdsec_captcha_renderer",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_RENDER_VCL.format(
                        RECAPTCHA_SITE_KEY=self.recaptcha_site_key
                    ),
                    version=self.version,
                    type="error",
                ),
                VCL(
                    name=f"crowdsec_captcha_validator",
                    service_id=self.service_id,
                    action=vcl_templates.CAPTCHA_VALIDATOR_VCL.format(
                        JWT_SECRET=jwt_secret,
                        COOKIE_EXPIRY_DURATION=self.captcha_expiry_duration,
                    ),
                    version=self.version,
                    type="deliver",
                ),
                VCL(
                    name=f"crowdsec_captcha_google_backend",
                    service_id=self.service_id,
                    action=vcl_templates.GOOGLE_BACKEND.format(SERVICE_ID=self.service_id),
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

    async def transform_state(self, new_state: Dict[str, str]):
        """
        This method transforms the configuration of the service according to the "new_state".
        "new_state" is mapping of item->action. Eg  {"1.2.3.4": "ban", "CN": "captcha", "1234": "ban"}.
        item is string representation of IP or Country or AS Number.
        """
        new_acl_state_by_action = {action: set() for action in self.supported_actions}

        prev_countries_by_action = {
            action: countries.copy() for action, countries in self.countries_by_action.items()
        }
        prev_autonomoussystems_by_action = {
            action: systems.copy() for action, systems in self.autonomoussystems_by_action.items()
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
            expired_countries = prev_countries_by_action[action] - self.countries_by_action[action]
            if expired_countries:
                logger.info(f"{action} removed for countries {expired_countries} ")

            expired_systems = (
                prev_autonomoussystems_by_action[action] - self.autonomoussystems_by_action[action]
            )
            if expired_systems:
                logger.info(f"{action} removed for AS {expired_systems} ")

            new_countries = self.countries_by_action[action] - prev_countries_by_action[action]
            if new_countries:
                logger.info(f"countries {new_countries} will get {action} ")

            new_systems = (
                self.autonomoussystems_by_action[action] - prev_autonomoussystems_by_action[action]
            )
            if new_systems:
                logger.info(f"AS {new_systems} will get {action}")

        await self.commit()

    async def commit(self):
        async with trio.open_nursery() as n:
            for action in self.vcl_by_action:
                n.start_soon(self.acl_collection_by_action[action].commit)
                n.start_soon(self.update_vcl, action)

        if self._first_time and self.activate:
            logger.debug(
                with_suffix(
                    f"activating new service version {self.version}",
                    service_id=self.service_id,
                )
            )
            await self.api.activate_service_version(self.service_id, self.version)
            logger.info(
                with_suffix(
                    f"activated new service version {self.version}",
                    service_id=self.service_id,
                )
            )
            self._first_time = False

    async def update_vcl(self, action: str):
        vcl = self.vcl_by_action[action]
        new_conditional = self.generate_conditional_for_action(action)
        if new_conditional != vcl.conditional:
            vcl.conditional = new_conditional
            vcl = await self.api.create_or_update_vcl(vcl)
            self.vcl_by_action[action] = vcl

    @staticmethod
    def generate_equalto_conditions_for_items(items: Iterable, equal_to: str, quote=False):
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
        async with trio.open_nursery() as n:
            for action, acl_col in self.acl_collection_by_action.items():
                n.start_soon(acl_col.refresh_from_fastly)
        logger.info(f"Done reloading ACLS for {self.service_id}")
