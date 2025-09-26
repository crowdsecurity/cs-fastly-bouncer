import datetime
import ipaddress
import logging
import random
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin

import httpx
import trio
from dateutil.parser import parse as parse_date
from fastly_bouncer.utils import with_suffix

logger: logging.Logger = logging.getLogger("")

ACL_CAPACITY = 1000  # Max number of entries an ACL can hold
ACL_BATCH_SIZE = (
    1000  # Max number of entries that can be added/removed in a single API call
)
ENTRIES_PER_PAGE = 1000

# Retry configuration for rate limiting
MAX_RETRIES = 5
BASE_RETRY_DELAY = 1.0  # Base delay in seconds
MAX_RETRY_DELAY = 32.0  # Maximum delay in seconds


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


async def calculate_retry_delay(attempt: int) -> float:
    """
    Calculate exponential backoff delay with jitter for retry attempts.
    """
    if attempt <= 0:
        return 0

    # Exponential backoff: base_delay * 2^(attempt-1)
    delay = BASE_RETRY_DELAY * (2 ** (attempt - 1))

    # Cap the delay at MAX_RETRY_DELAY
    delay = min(delay, MAX_RETRY_DELAY)

    # Add jitter (±25% of the delay) to avoid thundering herd
    jitter = delay * 0.25 * (2 * random.random() - 1)
    return delay + jitter


async def retry_on_rate_limit(func, *args, **kwargs):
    """
    Retry wrapper for API calls that may encounter 429 rate limits.
    Implements exponential backoff with jitter.
    """
    last_exception = None

    for attempt in range(MAX_RETRIES + 1):  # 0 to MAX_RETRIES
        try:
            return await func(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:  # Rate limit
                last_exception = e
                if attempt < MAX_RETRIES:  # Don't sleep on the last attempt
                    delay = await calculate_retry_delay(attempt + 1)
                    logger.warning(
                        f"Rate limited (429), retrying in {delay:.2f}s (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    await trio.sleep(delay)
                    continue
            # Re-raise non-429 errors immediately
            raise
        except Exception:
            # Re-raise non-HTTP errors immediately
            raise

    # If we get here, all retries failed
    logger.error(f"All {MAX_RETRIES} retry attempts failed for rate-limited request")
    raise last_exception


async def log_and_raise_on_error(response):
    if response.status_code >= 400:
        try:
            error_body = response.text
            logger.error(
                f"HTTP {response.status_code} error for {response.request.method} {response.url}: {error_body}"
            )
        except Exception:
            logger.error(
                f"HTTP {response.status_code} error for {response.request.method} {response.url}"
            )
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
            event_hooks={"response": [log_and_raise_on_error]},
        )

    async def get_candidate_version(self, service_id: str) -> str:
        """
        Get active the version of the service if any.
        Else returns the version which was last updated.
        """
        service_versions_resp = await self.session.get(
            self.api_url(f"/service/{service_id}/version")
        )
        service_versions = service_versions_resp.json()

        # First, look for an active version
        for service_version in service_versions:
            if service_version.get("active", False):
                logger.info(
                    with_suffix(f"Found active version: {service_version['number']}")
                )
                return str(service_version["number"])

        # If no active version found, fall back to the most recently updated version
        version_to_clone = None
        last_updated = None
        for service_version in service_versions:
            if not last_updated:
                version_to_clone = service_version["number"]
                last_updated = parse_date(service_version["updated_at"])
            elif last_updated < parse_date(service_version["updated_at"]):
                last_updated = parse_date(service_version["updated_at"])
                version_to_clone = service_version["number"]
        logger.info(with_suffix(f"Using last updated version: {version_to_clone}"))
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
            self.api_url(
                f"/service/{vcl.service_id}/version/{vcl.version}/snippet/{vcl.name}"
            )
        )
        return resp.json()

    async def get_all_acls(self, service_id, version) -> List[ACL]:
        resp = await self.session.get(
            self.api_url(f"/service/{service_id}/version/{version}/acl")
        )
        acls = resp.json()
        return [
            ACL(id=acl["id"], name=acl["name"], service_id=service_id, version=version)
            for acl in acls
        ]

    async def delete_acl(self, acl: ACL):
        resp = await self.session.delete(
            self.api_url(
                f"/service/{acl.service_id}/version/{acl.version}/acl/{acl.name}"
            )
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
        Creates a new version for service.
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
                "comment": (
                    f"Created by CrowdSec. {comment} Cloned from version {version}. "
                    f"Created at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
                )
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

    async def refresh_acl_entries(self, acl: ACL) -> ACL:
        acl.entries = {}
        page = 1
        per_page = ENTRIES_PER_PAGE

        while True:
            resp = await self.session.get(
                self.api_url(
                    f"/service/{acl.service_id}/acl/{acl.id}/entries?per_page={per_page}&page={page}"
                )
            )
            entries_page = resp.json()

            # Process entries from this page
            for entry in entries_page:
                acl.entries[f"{entry['ip']}/{entry['subnet']}"] = entry["id"]

            # Check if we've gotten all entries (less than per_page means last page)
            if len(entries_page) < per_page:
                break

            page += 1

        logger.debug(
            with_suffix(f"refreshed {len(acl.entries)} ACL entries", acl_id=acl.id)
        )
        return acl

    async def process_acl(self, acl: ACL) -> bool:
        logger.debug(
            with_suffix(f"entries to delete {acl.entries_to_delete}", acl_id=acl.id)
        )
        logger.debug(with_suffix(f"entries to add {acl.entries_to_add}", acl_id=acl.id))
        update_entries = []
        successfully_processed_additions = set()
        successfully_processed_deletions = set()

        for entry_to_add in acl.entries_to_add:
            if entry_to_add in acl.entries:
                successfully_processed_additions.add(
                    entry_to_add
                )  # Already exists, mark as processed
                continue
            network = ipaddress.ip_network(entry_to_add)
            ip, subnet = str(network.network_address), network.prefixlen
            update_entries.append(
                {"op": "create", "ip": ip, "subnet": subnet, "item": entry_to_add}
            )

        for entry_to_delete in acl.entries_to_delete:
            if entry_to_delete not in acl.entries:
                successfully_processed_deletions.add(
                    entry_to_delete
                )  # Doesn't exist, mark as processed
                continue
            update_entries.append(
                {
                    "op": "delete",
                    "id": acl.entries[entry_to_delete],
                    "item": entry_to_delete,
                }
            )

        if not update_entries:
            # Clear items that didn't need API calls (already existed or didn't exist)
            acl.entries_to_add -= successfully_processed_additions
            acl.entries_to_delete -= successfully_processed_deletions
            return True  # Success - no operations needed

        logger.debug(
            with_suffix(
                f"processing {len(update_entries)} operations in batches of {ACL_BATCH_SIZE}",
                acl_id=acl.id,
            )
        )

        # Only ACL_BATCH_SIZE operations per request can be done on an acl.
        async def process_batch(batch_entries, batch_idx):
            async def _patch_acl_entries():
                """Inner function to perform the actual ACL patch request."""
                # Remove the tracking field before sending to API
                api_batch = [
                    {k: v for k, v in entry.items() if k != "item"}
                    for entry in batch_entries
                ]
                request_body = {"entries": api_batch}
                return await self.session.patch(
                    self.api_url(f"/service/{acl.service_id}/acl/{acl.id}/entries"),
                    json=request_body,
                )

            try:
                # Use retry logic for the ACL patch request
                await retry_on_rate_limit(_patch_acl_entries)
                logger.debug(
                    with_suffix(
                        f"successfully processed batch {batch_idx} with {len(batch_entries)} operations",
                        acl_id=acl.id,
                    )
                )
            except Exception as e:
                logger.error(
                    with_suffix(
                        f"failed to process batch {batch_idx} with {len(batch_entries)} operations: {e}",
                        acl_id=acl.id,
                    )
                )
                # Remove items from successfully_processed sets since they failed
                for entry in batch_entries:
                    if entry["op"] == "create":
                        successfully_processed_additions.discard(entry["item"])
                    elif entry["op"] == "delete":
                        successfully_processed_deletions.discard(entry["item"])

        # Process batches with error handling
        for i in range(0, len(update_entries), ACL_BATCH_SIZE):
            update_entries_batch = update_entries[i : i + ACL_BATCH_SIZE]
            # Track which items are in this batch
            for entry in update_entries_batch:
                if entry["op"] == "create":
                    successfully_processed_additions.add(entry["item"])
                elif entry["op"] == "delete":
                    successfully_processed_deletions.add(entry["item"])

            batch_idx = i // ACL_BATCH_SIZE + 1
            await process_batch(update_entries_batch, batch_idx)

        acl = await self.refresh_acl_entries(acl)

        # Remove all items that were successfully sent to the API
        acl.entries_to_add -= successfully_processed_additions
        acl.entries_to_delete -= successfully_processed_deletions

        additions = len(successfully_processed_additions)
        deletions = len(successfully_processed_deletions)
        logger.debug(
            with_suffix(
                f"cleared {additions} additions and {deletions} deletions from pending",
                acl_id=acl.id,
            )
        )

        # Return True if we have pending operations that still need to be processed
        # This indicates partial failure - some operations didn't complete
        has_pending_operations = bool(acl.entries_to_add or acl.entries_to_delete)
        return not has_pending_operations  # Success if no pending operations remain

    @staticmethod
    def api_url(endpoint: str) -> str:
        return urljoin(FastlyAPI.base_url, endpoint)

    @staticmethod
    def check_for_errors(resp, *args, **kwargs):
        resp.raise_for_status()
