import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import trio
import yaml
from fastly_bouncer.fastly_api import FastlyAPI
from fastly_bouncer.utils import DEFAULT_DECISION_SOURCES, VERSION, are_filled_validator


@dataclass
class CrowdSecConfig:
    lapi_key: str
    lapi_url: str = "http://localhost:8080/"
    include_scenarios_containing: List[str] = field(default_factory=list)
    exclude_scenarios_containing: List[str] = field(default_factory=list)
    only_include_decisions_from: List[str] = field(
        default_factory=lambda: DEFAULT_DECISION_SOURCES.copy()
    )
    insecure_skip_verify: bool = False
    key_path: str = ""
    cert_path: str = ""
    ca_cert_path: str = ""

    def __post_init__(self):
        # Only validate required fields (exclude optional fields that can be None)
        required_fields = {"lapi_key": self.lapi_key, "lapi_url": self.lapi_url}
        are_filled_validator(**required_fields)


@dataclass
class FastlyServiceConfig:
    id: str
    recaptcha_site_key: str
    recaptcha_secret_key: str
    activate: bool = False
    max_items: int = 20000
    captcha_cookie_expiry_duration: str = "1800"
    reference_version: Optional[str] = None

    def __post_init__(self):
        # Exclude reference_version from validation since it can be None
        fields_to_validate = {
            key: getattr(self, key)
            for key in asdict(self).keys()
            if key != "reference_version"
        }
        are_filled_validator(**fields_to_validate)


@dataclass
class FastlyAccountConfig:
    account_token: str
    services: List[FastlyServiceConfig]


def _filter_and_warn_unknown_fields(
    data_dict: Dict, dataclass_type, context: str
) -> Dict:
    """Filter out unknown fields and warn about them"""
    valid_fields = {f.name for f in dataclass_type.__dataclass_fields__.values()}
    filtered_data = {}

    for key, value in data_dict.items():
        if key in valid_fields:
            filtered_data[key] = value
        else:
            print(
                f"Warning: Unknown configuration parameter '{key}' in {context} will be removed.",
                file=sys.stderr,
            )

    return filtered_data


def fastly_config_from_dict(data: Dict) -> List[FastlyAccountConfig]:
    account_configs: List[FastlyAccountConfig] = []
    for account_cfg in data:
        service_configs: List[FastlyServiceConfig] = []
        for service_cfg in account_cfg["services"]:
            filtered_service_cfg = _filter_and_warn_unknown_fields(
                service_cfg,
                FastlyServiceConfig,
                f"Service '{service_cfg.get('id', 'unknown')}'",
            )
            service_configs.append(FastlyServiceConfig(**filtered_service_cfg))
        account_configs.append(
            FastlyAccountConfig(
                account_token=account_cfg["account_token"], services=service_configs
            )
        )
    return account_configs


@dataclass
class Config:
    log_level: str
    log_mode: str
    log_file: str
    update_frequency: int
    crowdsec_config: CrowdSecConfig
    cache_path: str = (
        "/var/lib/crowdsec/crowdsec-fastly-bouncer/cache/fastly-cache.json"
    )
    bouncer_version: str = VERSION
    fastly_account_configs: List[FastlyAccountConfig] = field(default_factory=list)
    acl_fast_creation: bool = False

    def get_log_level(self) -> int:
        log_level_by_str = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
        }
        return log_level_by_str.get(self.log_level.lower())

    def __post_init__(self):
        for i, account_config in enumerate(self.fastly_account_configs):
            if not account_config.account_token:
                raise ValueError(f" {i + 1}th has no token specified in config")
            if not account_config.services:
                raise ValueError(f" {i + 1}th has no service specified in config")


def parse_config_file(path: Path):
    if not path.is_file():
        raise FileNotFoundError(f"Config file at {path} doesn't exist")
    with open(path) as f:
        data = yaml.safe_load(f)

        # Filter and warn about unknown root-level parameters
        filtered_data = _filter_and_warn_unknown_fields(
            data, Config, "root configuration"
        )

        # Filter and warn about unknown crowdsec_config parameters
        crowdsec_data = filtered_data["crowdsec_config"]
        filtered_crowdsec_data = _filter_and_warn_unknown_fields(
            crowdsec_data, CrowdSecConfig, "crowdsec_config"
        )

        return Config(
            crowdsec_config=CrowdSecConfig(
                lapi_key=filtered_crowdsec_data["lapi_key"],
                lapi_url=filtered_crowdsec_data.get(
                    "lapi_url", "http://localhost:8080/"
                ),
                include_scenarios_containing=filtered_crowdsec_data.get(
                    "include_scenarios_containing", []
                ),
                exclude_scenarios_containing=filtered_crowdsec_data.get(
                    "exclude_scenarios_containing", []
                ),
                only_include_decisions_from=filtered_crowdsec_data.get(
                    "only_include_decisions_from", DEFAULT_DECISION_SOURCES
                ),
                insecure_skip_verify=filtered_crowdsec_data.get(
                    "insecure_skip_verify", False
                ),
                key_path=filtered_crowdsec_data.get("key_path", ""),
                cert_path=filtered_crowdsec_data.get("cert_path", ""),
                ca_cert_path=filtered_crowdsec_data.get("ca_cert_path", ""),
            ),
            fastly_account_configs=fastly_config_from_dict(
                filtered_data["fastly_account_configs"]
            ),
            log_level=filtered_data["log_level"],
            log_mode=filtered_data["log_mode"],
            log_file=filtered_data["log_file"],
            update_frequency=int(filtered_data["update_frequency"]),
            cache_path=filtered_data["cache_path"],
            acl_fast_creation=filtered_data.get("acl_fast_creation", False),
        )


def default_config():
    return Config(
        log_level="info",
        log_mode="stdout",
        log_file="/var/log/crowdsec-fastly-bouncer.log",  # FIXME: This needs root permissions
        crowdsec_config=CrowdSecConfig(lapi_key="<LAPI_KEY>"),
        update_frequency=10,
    )


class ConfigGenerator:
    service_name_by_service_id: Dict[str, str] = {}

    @staticmethod
    async def generate_config(
        comma_separated_fastly_tokens: str, base_config: Config = default_config()
    ) -> str:
        fastly_tokens = comma_separated_fastly_tokens.split(",")
        fastly_tokens = list(map(lambda token: token.strip(), fastly_tokens))
        for token in fastly_tokens:
            account_cfg = await ConfigGenerator.generate_config_for_account(token)
            base_config.fastly_account_configs.append(account_cfg)
        return ConfigGenerator.add_comments(yaml.safe_dump(asdict(base_config)))

    @staticmethod
    def add_comments(config: str):
        lines = config.split("\n")
        for i, line in enumerate(lines):
            for (
                service_id,
                service_name,
            ) in ConfigGenerator.service_name_by_service_id.items():
                has_service_id = False
                if service_id in line:
                    lines[i] = f"{line}  # {service_name}"
                    has_service_id = True
                    break
                if has_service_id:
                    break

            if "activate:" in line:
                lines[i] = (
                    f"{line}  # Set to true, to activate the new config in production"
                )
                continue

            if "captcha_cookie_expiry_duration" in line:
                lines[i] = (
                    f"{line}  # Duration(in second) to persist the cookie containing proof of solving captcha"
                )
                continue

            if "reference_version:" in line:
                lines[i] = (
                    f"{line}  # Optional: specify a specific version to clone from instead of the active version"
                )
                continue

            if "acl_fast_creation:" in line:
                lines[i] = (
                    f"{line}  # Set to true to create ACLs in parallel (faster but random order)"
                )
                continue

        return "\n".join(lines)

    @staticmethod
    async def generate_config_for_service(service_id: str, sender_chan):
        async with sender_chan:
            await sender_chan.send(
                FastlyServiceConfig(
                    id=service_id,
                    recaptcha_site_key="<RECAPTCHA_SITE_KEY>",
                    recaptcha_secret_key="<RECAPTCHA_SECRET_KEY>",
                    activate=False,
                )
            )

    @staticmethod
    async def generate_config_for_account(fastly_token: str) -> FastlyAccountConfig:
        api = FastlyAPI(fastly_token)
        service_ids_with_name = await api.get_all_service_ids(with_name=True)
        for service_id, service_name in service_ids_with_name:
            ConfigGenerator.service_name_by_service_id[service_id] = service_name
        service_ids = list(map(lambda x: x[0], service_ids_with_name))
        service_configs: List[FastlyServiceConfig] = []

        sender, receiver = trio.open_memory_channel(0)
        async with trio.open_nursery() as n:
            async with sender:
                for service_id in service_ids:
                    n.start_soon(
                        ConfigGenerator.generate_config_for_service,
                        service_id,
                        sender.clone(),
                    )

            async with receiver:
                async for service_cfg in receiver:
                    service_configs.append(service_cfg)

        return FastlyAccountConfig(account_token=fastly_token, services=service_configs)

    @staticmethod
    async def edit_config(
        comma_separated_fastly_tokens: str, existing_config: Config
    ) -> str:
        fastly_tokens = comma_separated_fastly_tokens.split(",")
        fastly_tokens = list(map(lambda token: token.strip(), fastly_tokens))

        # Generate new config with fresh data from tokens
        new_config = Config(
            log_level=existing_config.log_level,
            log_mode=existing_config.log_mode,
            log_file=existing_config.log_file,
            update_frequency=existing_config.update_frequency,
            crowdsec_config=existing_config.crowdsec_config,
            cache_path=existing_config.cache_path,
            bouncer_version=existing_config.bouncer_version,
            acl_fast_creation=existing_config.acl_fast_creation,
        )

        # Generate fresh account configs with new tokens
        for token in fastly_tokens:
            account_cfg = await ConfigGenerator.generate_config_for_account(token)
            new_config.fastly_account_configs.append(account_cfg)

        # Merge service configurations from existing config
        merged_config = ConfigGenerator.merge_service_configs(
            existing_config, new_config
        )

        return ConfigGenerator.add_comments(yaml.safe_dump(asdict(merged_config)))

    @staticmethod
    def merge_service_configs(existing_config: Config, new_config: Config) -> Config:
        # Create a mapping of service_id -> existing service config
        existing_services = {}
        for account in existing_config.fastly_account_configs:
            for service in account.services:
                existing_services[service.id] = service

        # Merge configurations for each new account
        for new_account in new_config.fastly_account_configs:
            for i, new_service in enumerate(new_account.services):
                if new_service.id in existing_services:
                    existing_service = existing_services[new_service.id]
                    # Preserve existing service configuration including reference_version
                    new_account.services[i] = FastlyServiceConfig(
                        id=new_service.id,
                        recaptcha_site_key=existing_service.recaptcha_site_key,
                        recaptcha_secret_key=existing_service.recaptcha_secret_key,
                        activate=existing_service.activate,
                        max_items=existing_service.max_items,
                        captcha_cookie_expiry_duration=existing_service.captcha_cookie_expiry_duration,
                        reference_version=existing_service.reference_version,
                    )

        return new_config


def print_config(cfg, o_arg):
    if not o_arg:
        print(cfg)
    else:
        print(f"Writing config to {o_arg}", file=sys.stdout)
        with open(o_arg, "w") as f:
            f.write(cfg)
