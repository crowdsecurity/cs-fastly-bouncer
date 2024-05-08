import datetime
import ipaddress
import logging
from dataclasses import asdict, dataclass, field
from functools import partial
from typing import Dict, List, Set
from urllib.parse import urljoin

import httpx
import trio
from dateutil.parser import parse as parse_date

from fastly_bouncer.utils import with_suffix

logger: logging.Logger = logging.getLogger("")


ACL_CAPACITY = 1000 # as of 2024-05
ACL_BATCH_SIZE = 1000 # as of 2024-05

@dataclass
class ACL:
    id: str
    name: str
    service_id: str
    version: str
    entries_to_add: Set[str] = field(default_factory=set)
    entries_to_delete: Set[str] = field(default_factory=set)
    entries: Dict[str, str] = field(default_factory=dict)
    entry_count: int = 0
    created: bool = False

    def is_full(self) -> bool:
        is_full = self.entry_count == ACL_CAPACITY
        return is_full

    def as_jsonable_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "service_id": self.service_id,
            "version": self.version,
            "entries_to_add": list(self.entries_to_add),
            "entries_to_delete": list(self.entries_to_delete),
            "entries": self.entries,
            "entry_count": self.entry_count,
            "created": self.created,
        }

    def as_set(self) -> Set[str]:
        return set([ip_subnet for ip_subnet, _ in self.entries.items()])

@dataclass
class VCL:
    name: str
    service_id: str
    version: str
    action: str
    conditional: str = ""
    type: str = "recv"
    dynamic: str = "1"
    id: str = ""

    def as_jsonable_dict(self):
        return asdict(self)

    def to_dict(self):
        if self.conditional:
            content = f"{self.conditional} {{ {self.action} }}"
        else:
            content = self.action
        return {
            "name": self.name,
            "service_id": self.service_id,
            "version": self.version,
            "type": self.type,
            "content": content,
            "dynamic": self.dynamic,
        }


async def raise_on_4xx_5xx(response):
    response.raise_for_status()


class FastlyAPI:
    base_url = "https://api.fastly.com"

    def __init__(self, token):
        self._token = token
        self._acl_count = 0
        self.session = httpx.AsyncClient(
            headers=httpx.Headers({"Fastly-Key": self._token}),
            timeout=httpx.Timeout(connect=30, read=None, write=15, pool=None),
            transport=httpx.AsyncHTTPTransport(retries=3),
            event_hooks={"response": [raise_on_4xx_5xx]},
        )

    async def get_version_to_clone(self, service_id: str) -> str:
        """
        Gets the version to clone from. If service has active version, then the active version will be cloned.
        Else the the version which was last updated would be cloned
        """

        service_versions_resp = await self.session.get(
            self.api_url(f"/service/{service_id}/version")
        )
        service_versions = service_versions_resp.json()

        version_to_clone = None
        last_updated = None
        for service_version in service_versions:
            if not last_updated:
                version_to_clone = service_version["number"]
            elif last_updated < parse_date(service_version["updated_at"]):
                last_updated = parse_date(service_version["updated_at"])
                version_to_clone = service_version["number"]

        return str(version_to_clone)

    async def get_all_service_ids(self, with_name=False) -> List[str]:
        current_page = 1
        per_page = 50
        all_service_ids = []
        while True:
            resp = await self.session.get(
                self.api_url(f"/service?page={current_page}&per_page={per_page}")
            )
            services = resp.json()
            for service in services:
                if with_name:
                    all_service_ids.append((service["id"], service["name"]))
                else:
                    all_service_ids.append(service["id"])
            if len(services) < per_page:
                return all_service_ids

    async def get_all_vcls(self, service_id, version) -> List[VCL]:
        vcls = await self.session.get(
            self.api_url(f"/service/{service_id}/version/{version}/snippet")
        )
        vcls = vcls.json()
        return [
            VCL(
                name=vcl["name"],
                service_id=vcl["service_id"],
                dynamic=vcl["dynamic"],
                id=vcl["id"],
                version=vcl["version"],
                action="",
            )
            for vcl in vcls
        ]

    async def activate_service_version(self, service_id: str, version: str):
        resp = await self.session.put(
            self.api_url(f"/service/{service_id}/version/{version}/activate")
        )
        resp.json()

    async def delete_vcl(self, vcl: VCL):
        resp = await self.session.delete(
            self.api_url(f"/service/{vcl.service_id}/version/{vcl.version}/snippet/{vcl.name}")
        )
        return resp.json()

    async def get_all_acls(self, service_id, version) -> List[ACL]:
        resp = await self.session.get(self.api_url(f"/service/{service_id}/version/{version}/acl"))
        acls = resp.json()
        return [
            ACL(id=acl["id"], name=acl["name"], service_id=service_id, version=version)
            for acl in acls
        ]

    async def delete_acl(self, acl: ACL):
        resp = await self.session.delete(
            self.api_url(f"/service/{acl.service_id}/version/{acl.version}/acl/{acl.name}")
        )
        return resp

    async def clear_crowdsec_resources(self, service_id, version):
        """
        The version of the service provided must not be locked.
        """
        all_acls = await self.get_all_acls(service_id, version)
        all_acls = list(filter(lambda acl: acl.name.startswith("crowdsec"), all_acls))

        all_vcls = await self.get_all_vcls(service_id, version)
        all_vcls = list(filter(lambda vcl: vcl.name.startswith("crowdsec"), all_vcls))
        if not all_vcls and not all_acls:
            return

        async with trio.open_nursery() as n:
            for acl in all_acls:
                n.start_soon(self.delete_acl, acl)
            for vcl in all_vcls:
                n.start_soon(self.delete_vcl, vcl)

    async def clone_version_for_service_from_given_version(
        self, service_id: str, version: str, comment=""
    ) -> str:
        """
        Creates new version for service.
        Returns the new version.
        """
        if not comment:
            comment = ""
        resp = await self.session.put(
            self.api_url(f"/service/{service_id}/version/{version}/clone")
        )
        resp = resp.json()
        tmp = await self.session.put(
            self.api_url(
                f"/service/{service_id}/version/{resp['number']}",
            ),
            json={
                "comment": f"Created by CrowdSec. {comment} Cloned from version {version}. Created at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
            },
        )
        tmp.json()
        return str(resp["number"])

    async def create_acl_for_service(self, service_id, version, name=None) -> ACL:
        """
        Create an ACL resource for the given service_id and version. If "name"
        parameter is not specified, a random name would be used for the ACL.
        Returns the id of the ACL.
        """
        if not name:
            name = f"acl_{str(self._acl_count)}"

        r = await self.session.post(
            self.api_url(f"/service/{service_id}/version/{version}/acl"),
            data=f"name={name}",
        )
        resp = r.json()
        self._acl_count += 1
        return ACL(
            id=resp["id"],
            service_id=service_id,
            version=str(version),
            name=name,
            created=True,
        )

    async def create_or_update_vcl(self, vcl: VCL) -> VCL:
        if not vcl.id:
            vcl = await self.create_vcl(vcl)
        else:
            vcl = await self.update_dynamic_vcl(vcl)
        return vcl

    async def is_service_version_locked(self, service_id, version) -> bool:
        resp = await self.session.get(self.api_url(f"/service/{service_id}/version/{version}"))
        resp = resp.json()
        return resp["locked"]

    async def create_vcl(self, vcl: VCL):
        if vcl.id:
            return vcl
        resp = await self.session.post(
            self.api_url(f"/service/{vcl.service_id}/version/{vcl.version}/snippet"),
            data=vcl.to_dict(),
        )
        resp = resp.json()
        vcl.id = resp["id"]
        return vcl

    async def update_dynamic_vcl(self, vcl: VCL):
        resp = await self.session.put(
            self.api_url(f"/service/{vcl.service_id}/snippet/{vcl.id}"),
            data=vcl.to_dict(),
        )
        resp.json()
        return vcl

    async def refresh_acl_entries(self, acl: ACL) -> None:
        resp = await self.session.get(
            self.api_url(f"/service/{acl.service_id}/acl/{acl.id}/entries?per_page={ACL_BATCH_SIZE}")
        )
        resp = resp.json()
        acl.entries = {}
        for entry in resp:
            acl.entries[f"{entry['ip']}/{entry['subnet']}"] = entry["id"]

    async def process_acl(self, acl: ACL):
        logger.debug(with_suffix(f"entries to delete %s", acl_id=acl.id), acl.entries_to_delete)
        logger.debug(with_suffix(f"entries to add %s", acl_id=acl.id), acl.entries_to_add)
        update_entries = []
        for entry_to_add in acl.entries_to_add:
            if entry_to_add in acl.entries:
                continue
            network = ipaddress.ip_network(entry_to_add)
            ip, subnet = str(network.network_address), network.prefixlen
            update_entries.append({"op": "create", "ip": ip, "subnet": subnet})

        for entry_to_delete in acl.entries_to_delete:
            update_entries.append(
                {
                    "op": "delete",
                    "id": acl.entries[entry_to_delete],
                }
            )

        if not update_entries:
            return

        # Only ACL_BATCH_SIZE operations per request can be done on an acl.
        async with trio.open_nursery() as n:
            for i in range(0, len(update_entries), ACL_BATCH_SIZE):
                update_entries_batch = update_entries[i : i + ACL_BATCH_SIZE]
                request_body = {"entries": update_entries_batch}
                f = partial(self.session.patch, json=request_body)
                n.start_soon(
                    f,
                    self.api_url(f"/service/{acl.service_id}/acl/{acl.id}/entries"),
                )

        await self.refresh_acl_entries(acl)
        # TODO BUG: the acls are updated but the service state is not

    @staticmethod
    def api_url(endpoint: str) -> str:
        return urljoin(FastlyAPI.base_url, endpoint)

    @staticmethod
    def check_for_errors(resp, *args, **kwargs):
        resp.raise_for_status()
