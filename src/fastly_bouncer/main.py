import argparse
import json
import logging
import signal
import sys
from logging.handlers import RotatingFileHandler
from math import ceil
from pathlib import Path
from typing import List

import trio
from fastly_bouncer.config import (
    Config,
    ConfigGenerator,
    FastlyAccountConfig,
    FastlyServiceConfig,
    parse_config_file,
    print_config,
)
from fastly_bouncer.fastly_api import ACL_CAPACITY, FastlyAPI
from fastly_bouncer.service import ACLCollection, Service
from fastly_bouncer.utils import (
    SUPPORTED_ACTIONS,
    VERSION,
    CustomFormatter,
    get_default_logger,
    with_suffix,
)
from pycrowdsec.client import StreamClient

logger: logging.Logger = get_default_logger()

exiting = False


def sigterm_signal_handler(signum, frame):
    global exiting
    exiting = True
    logger.info("exiting")


signal.signal(signal.SIGTERM, sigterm_signal_handler)
signal.signal(signal.SIGINT, sigterm_signal_handler)


async def setup_action_for_service(
    fastly_api: FastlyAPI,
    action: str,
    service_cfg: FastlyServiceConfig,
    service_version,
    fast_creation: bool = False,
) -> ACLCollection:

    acl_count = ceil(service_cfg.max_items / ACL_CAPACITY)
    acl_collection = ACLCollection(
        api=fastly_api,
        service_id=service_cfg.id,
        version=service_version,
        action=action,
        max_items=service_cfg.max_items,
        state=set(),
        fast_creation=fast_creation,
    )
    logger.info(
        with_suffix(
            f"creating acl collection of {acl_count} acls for {action} action",
            service_id=service_cfg.id,
        )
    )
    acls = await acl_collection.create_acls(acl_count)
    acl_collection.acls = acls
    logger.info(
        with_suffix(
            f"created acl collection for {action} action",
            service_id=service_cfg.id,
        )
    )
    return acl_collection


async def setup_service(
    service_cfg: FastlyServiceConfig,
    fastly_api: FastlyAPI,
    cleanup_mode: bool,
    sender_chan: trio.MemorySendChannel,
    fast_creation: bool = False,
):
    comment = None
    service_id = service_cfg.id
    if cleanup_mode:
        comment = "Clone cleaned from CrowdSec resources"

    # Use reference_version if provided, otherwise get the active version
    if service_cfg.reference_version:
        logger.info(
            with_suffix(
                f"Using reference_version value: {service_cfg.reference_version}"
            )
        )
        version_to_clone = service_cfg.reference_version
    else:
        version_to_clone = await fastly_api.get_candidate_version(service_id)
    version = await fastly_api.clone_version_for_service_from_given_version(
        service_cfg.id, version_to_clone, comment
    )
    logger.info(
        with_suffix(
            f"New version {version} cloned from version {version_to_clone} (service_id=${service_id})"
        )
    )

    logger.info(
        with_suffix(
            "Cleaning existing crowdsec resources (if any)",
            service_id=service_cfg.id,
            version=version,
        )
    )

    await fastly_api.clear_crowdsec_resources(service_cfg.id, version)
    if cleanup_mode:
        sender_chan.close()
        return

    logger.debug(
        with_suffix(
            "Cleaned existing crowdsec resources (if any)",
            service_id=service_cfg.id,
            version=version,
        )
    )

    acl_collection_by_action = {}
    for action in SUPPORTED_ACTIONS:
        acl_collection = await setup_action_for_service(
            fastly_api, action, service_cfg, version, fast_creation
        )
        acl_collection_by_action[action] = acl_collection
        if not fast_creation:
            # Small delay to ensure proper ordering at Fastly API level
            await trio.sleep(1)

    async with sender_chan:
        s = Service(
            api=fastly_api,
            recaptcha_secret=service_cfg.recaptcha_secret_key,
            recaptcha_site_key=service_cfg.recaptcha_site_key,
            acl_collection_by_action=acl_collection_by_action,
            service_id=service_cfg.id,
            version=version,
            activate=service_cfg.activate,
            captcha_expiry_duration=service_cfg.captcha_cookie_expiry_duration,
        )
        await s.create_static_vcls()
        await sender_chan.send(s)


async def setup_account(
    account_cfg: FastlyAccountConfig,
    cleanup: bool,
    sender_chan,
    fast_creation: bool = False,
):
    fastly_api = FastlyAPI(account_cfg.account_token)
    new_services = []
    sender, receiver = trio.open_memory_channel(0)
    async with trio.open_nursery() as n:
        async with sender:
            for cfg in account_cfg.services:
                n.start_soon(
                    setup_service,
                    cfg,
                    fastly_api,
                    cleanup,
                    sender.clone(),
                    fast_creation,
                )

        async with receiver:
            async for service in receiver:
                new_services.append(service)

    async with sender_chan:
        await sender_chan.send(new_services)


async def setup_fastly_infra(config: Config, cleanup_mode):
    p = Path(config.cache_path)
    if p.exists():
        logger.info("Cache file exists")
        async with await trio.open_file(config.cache_path) as f:
            s = await f.read()
            if not s:
                logger.warning(f"Cache file at {config.cache_path} is empty")
            else:
                if not cleanup_mode:
                    try:
                        cache_content = json.loads(s)
                        if "service_states" in cache_content:
                            logger.info("Loading services from cache")
                            services = []
                            for service_state in cache_content["service_states"]:
                                try:
                                    service = Service.from_jsonable_dict(service_state)
                                    services.append(service)
                                except Exception as e:
                                    logger.error(
                                        f"Failed to load service from cache: {e}"
                                    )
                                    logger.info(
                                        "Cache appears corrupted, will create new infrastructure"
                                    )
                                    break
                            else:
                                if services:
                                    logger.info(
                                        "Successfully loaded services from cache"
                                    )
                                    return services
                        logger.info(
                            "Cache format invalid or no services found, will create new infrastructure"
                        )
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse cache file: {e}")
                        logger.info(
                            "Cache file corrupted, will create new infrastructure"
                        )
    else:
        p.parent.mkdir(exist_ok=True, parents=True)

    if cleanup_mode:
        logger.info("Cleaning fastly infra")
    else:
        logger.info("Setting up fastly infra")

    services = []
    sender, receiver = trio.open_memory_channel(0)
    async with trio.open_nursery() as n:
        async with sender:
            for cfg in config.fastly_account_configs:
                n.start_soon(
                    setup_account,
                    cfg,
                    cleanup_mode,
                    sender.clone(),
                    config.acl_fast_creation,
                )

        async for service_chunk in receiver:
            services.extend(service_chunk)

    logger.info("Fastly infra setup complete")
    return services


def set_logger(config: Config):
    list(map(logger.removeHandler, logger.handlers))
    logger.setLevel(config.get_log_level())
    if config.log_mode == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif config.log_mode == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    elif config.log_mode == "file":
        handler = RotatingFileHandler(config.log_file, mode="a+")
    else:
        raise ValueError(f"Unknown log mode {config.log_mode}")
    formatter = CustomFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(f"Starting fastly-bouncer-v{VERSION}")


def build_client_params(config: Config):
    # Build StreamClient parameters
    client_params = {
        "api_key": config.crowdsec_config.lapi_key,
        "lapi_url": config.crowdsec_config.lapi_url,
        "interval": config.update_frequency,
        "user_agent": f"fastly-bouncer/v{VERSION}",
        "scopes": ("ip", "range", "country", "as"),
    }
    # Origins to include decisions from
    if config.crowdsec_config.only_include_decisions_from:
        client_params["only_include_decisions_from"] = tuple(
            config.crowdsec_config.only_include_decisions_from
        )

    # Include/exclude scenarios
    if config.crowdsec_config.include_scenarios_containing:
        client_params["include_scenarios_containing"] = tuple(
            config.crowdsec_config.include_scenarios_containing
        )

    if config.crowdsec_config.exclude_scenarios_containing:
        client_params["exclude_scenarios_containing"] = tuple(
            config.crowdsec_config.exclude_scenarios_containing
        )

    # SSL/TLS options
    if config.crowdsec_config.insecure_skip_verify:
        client_params["insecure_skip_verify"] = True

    if config.crowdsec_config.key_path:
        client_params["key_path"] = config.crowdsec_config.key_path

    if config.crowdsec_config.cert_path:
        client_params["cert_path"] = config.crowdsec_config.cert_path

    if config.crowdsec_config.ca_cert_path:
        client_params["ca_cert_path"] = config.crowdsec_config.ca_cert_path

    return client_params


async def discover_existing_fastly_infra(config: Config) -> List[Service]:
    """Discover existing CrowdSec infrastructure in Fastly services."""
    discovered_services = []

    for account_cfg in config.fastly_account_configs:
        fastly_api = FastlyAPI(account_cfg.account_token)

        for service_cfg in account_cfg.services:
            try:
                # Get the active version (if any) or the latest updated version
                candidate_version = await fastly_api.get_candidate_version(
                    service_cfg.id
                )

                # Get existing CrowdSec ACLs from this version
                existing_acls = await fastly_api.get_all_acls(
                    service_cfg.id, candidate_version
                )
                crowdsec_acls = [
                    acl for acl in existing_acls if acl.name.startswith("crowdsec_")
                ]

                if not crowdsec_acls:
                    logger.info(
                        with_suffix(
                            "No existing CrowdSec ACLs found, skipping",
                            service_id=service_cfg.id,
                            version=candidate_version,
                        )
                    )
                    continue

                logger.info(
                    with_suffix(
                        f"Found {len(crowdsec_acls)} existing CrowdSec ACLs",
                        service_id=service_cfg.id,
                        version=candidate_version,
                    )
                )

                # Group ACLs by action
                acl_collection_by_action = {}
                for action in SUPPORTED_ACTIONS:
                    action_acls = [
                        acl
                        for acl in crowdsec_acls
                        if f"crowdsec_{action}_" in acl.name
                    ]
                    if action_acls:
                        # Create ACL collection for this action
                        acl_collection = ACLCollection(
                            api=fastly_api,
                            service_id=service_cfg.id,
                            version=candidate_version,
                            action=action,
                            max_items=service_cfg.max_items,
                            state=set(),  # Will be populated by reload_acls
                            acls=action_acls,
                            fast_creation=config.acl_fast_creation,
                        )
                        acl_collection_by_action[action] = acl_collection

                        logger.info(
                            with_suffix(
                                f"Discovered {len(action_acls)} ACLs for {action} action",
                                service_id=service_cfg.id,
                            )
                        )

                if acl_collection_by_action:
                    # Get existing VCLs
                    existing_vcls = await fastly_api.get_all_vcls(
                        service_cfg.id, candidate_version
                    )
                    crowdsec_vcls = [
                        vcl for vcl in existing_vcls if vcl.name.startswith("crowdsec_")
                    ]

                    # Create service object
                    service = Service(
                        api=fastly_api,
                        version=candidate_version,
                        service_id=service_cfg.id,
                        recaptcha_site_key=service_cfg.recaptcha_site_key,
                        recaptcha_secret=service_cfg.recaptcha_secret_key,
                        activate=service_cfg.activate,
                        captcha_expiry_duration=service_cfg.captcha_cookie_expiry_duration,
                        acl_collection_by_action=acl_collection_by_action,
                        _first_time=False,  # Not first time since infra already exists
                    )

                    # Set existing VCLs
                    service.vcl_by_action = {}
                    service.static_vcls = []
                    for vcl in crowdsec_vcls:
                        if vcl.name.endswith("_rule"):
                            if "ban" in vcl.name:
                                service.vcl_by_action["ban"] = vcl
                            elif "captcha" in vcl.name:
                                service.vcl_by_action["captcha"] = vcl
                        else:
                            service.static_vcls.append(vcl)

                    discovered_services.append(service)

                    logger.info(
                        with_suffix(
                            "Successfully discovered existing CrowdSec infrastructure",
                            service_id=service_cfg.id,
                            version=candidate_version,
                        )
                    )

            except Exception as e:
                logger.error(
                    with_suffix(
                        f"Failed to discover infra for service {service_cfg.id}: {e}",
                        service_id=service_cfg.id,
                    )
                )
                continue

    return discovered_services


async def refresh_acls_on_startup(services: List[Service]):
    """Refresh all ACL entries from Fastly on startup to ensure state synchronization."""
    logger.info("Refreshing local cache from Fastly on startup")

    async with trio.open_nursery() as n:
        for service in services:
            n.start_soon(service.reload_acls)

    logger.debug("Startup local cache refresh completed")


async def run(config: Config, services: List[Service]):
    # Build StreamClient parameters
    client_params = build_client_params(config)

    crowdsec_client = StreamClient(**client_params)
    crowdsec_client.run()
    await trio.sleep(
        2
    )  # Wait for initial polling by bouncer, so we start with a hydrated state
    if not crowdsec_client.is_running():
        return

    # Initialize previous_states to current state to avoid unnecessary cache updates
    previous_states = list(map(lambda service: service.as_jsonable_dict(), services))

    while True and not exiting:
        logger.debug(
            f"Retrieving decisions from LAPI with scopes {client_params['scopes']} "
            f"and origins {client_params['only_include_decisions_from']} "
            f"and include_scenarios_containing {client_params.get('include_scenarios_containing', [])} "
            f"and exclude_scenarios_containing {client_params.get('exclude_scenarios_containing', [])}"
        )
        new_state = crowdsec_client.get_current_decisions()
        logger.info(f"Retrieved {len(new_state)} active decisions from LAPI")

        # Track which services updated successfully
        service_results = {}

        async def track_service_update(service, service_results):
            success = await service.transform_state(new_state)
            service_results[id(service)] = success

        async with trio.open_nursery() as n:
            for s in services:
                n.start_soon(track_service_update, s, service_results)

        # Only update cache with services that successfully committed to Fastly
        successful_services = []
        failed_services = []
        for service in services:
            service_success = service_results.get(id(service), False)
            if service_success:
                successful_services.append(service)
            else:
                failed_services.append(service)
                logger.warning(
                    f"Service {service.service_id} had failures - keeping previous cache state"
                )

        # Generate new states only from successful services
        # For failed services, use their previous state from cache
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
                    # Fallback: use current state but log warning
                    logger.warning(
                        "No previous state found for failed service, using current state"
                    )
                    new_states.append(service.as_jsonable_dict())

        if new_states != previous_states:
            logger.debug("Updating local cache file with successful service updates")
            new_cache = {"service_states": new_states, "bouncer_version": VERSION}
            async with await trio.open_file(config.cache_path, "w") as f:
                await f.write(json.dumps(new_cache, indent=4))

            if failed_services:
                logger.info(
                    f"Local cache updated - {len(successful_services)} services succeeded, {len(failed_services)} failed"
                )
            else:
                logger.info("Local cache updated - all services succeeded")
            previous_states = new_states

        if exiting:
            return

        await trio.sleep(config.update_frequency)


async def start(config: Config, cleanup_mode, refresh_mode=False):

    if refresh_mode:
        logger.info(
            "Refresh mode enabled - discovering infrastructure from Fastly and refreshing local cache"
        )
        services = await discover_existing_fastly_infra(config)
        if not services:
            logger.error(
                "No existing CrowdSec infrastructure found in Fastly to refresh"
            )
            return
        await refresh_acls_on_startup(services)

        # Create initial cache after refresh to ensure cache file exists
        refreshed_states = list(
            map(lambda service: service.as_jsonable_dict(), services)
        )
        new_cache = {"service_states": refreshed_states, "bouncer_version": VERSION}
        async with await trio.open_file(config.cache_path, "w") as f:
            await f.write(json.dumps(new_cache, indent=4))
        logger.info("Local cache refreshed")

        await run(config, services)
        return

    services = await setup_fastly_infra(config, cleanup_mode)
    if cleanup_mode:
        if Path(config.cache_path).exists():
            logger.info("Cleaning cache")
            with open(config.cache_path, "w") as _:
                pass
        return

    await run(config, services)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", type=Path, help="Path to configuration file.")
    arg_parser.add_argument(
        "-d", help="Whether to cleanup resources.", action="store_true"
    )
    arg_parser.add_argument(
        "-e",
        help="Edit existing config with new tokens (requires both -g and -c).",
        action="store_true",
    )
    arg_parser.add_argument(
        "-g", type=str, help="Comma separated tokens to generate config for."
    )
    arg_parser.add_argument(
        "-o", type=str, help="Path to file to output the generated config."
    )
    arg_parser.add_argument(
        "-r",
        help="Refresh local cache from Fastly active versions (requires -c).",
        action="store_true",
    )
    arg_parser.add_help = True
    args = arg_parser.parse_args()

    # Validate refresh mode requirements
    if args.r:
        if not args.c:
            print("Refresh mode (-r) requires config file (-c)", file=sys.stderr)
            arg_parser.print_help()
            sys.exit(1)
        if args.d:
            print(
                "Refresh mode (-r) cannot be used with cleanup mode (-d)",
                file=sys.stderr,
            )
            arg_parser.print_help()
            sys.exit(1)
        if args.g or args.e or args.o:
            print(
                "Refresh mode (-r) can only be used with config file (-c)",
                file=sys.stderr,
            )
            arg_parser.print_help()
            sys.exit(1)

    # Validate edit mode requirements
    if args.e:
        if not args.g:
            print("Edit mode (-e) requires tokens (-g)", file=sys.stderr)
            arg_parser.print_help()
            sys.exit(1)
        if not args.c:
            print("Edit mode (-e) requires config file (-c)", file=sys.stderr)
            arg_parser.print_help()
            sys.exit(1)
        if args.o:
            print(
                "Edit mode (-e) cannot be used with output file (-o)", file=sys.stderr
            )
            arg_parser.print_help()
            sys.exit(1)

    # Handle config generation
    if args.g and not args.e:
        gc = trio.run(ConfigGenerator().generate_config, args.g)
        print_config(gc, args.o)
        sys.exit(0)

    # Handle config editing
    if args.e:
        if not args.c.exists():
            print(f"Config at {args.c} doesn't exist", file=sys.stderr)
            sys.exit(1)
        try:
            existing_config = parse_config_file(args.c)
            edited_config = trio.run(
                ConfigGenerator().edit_config, args.g, existing_config
            )

            # Write the edited config back to the original file
            with open(args.c, "w") as f:
                f.write(edited_config)

            print(f"Config successfully updated: {args.c}")
            sys.exit(0)
        except Exception as e:
            print(f"Got error {e} while editing config at {args.c}", file=sys.stderr)
            sys.exit(1)

    # Handle normal run
    if not args.g:
        if not args.c:
            print("Config file not provided", file=sys.stderr)
            arg_parser.print_help()
            sys.exit(1)
        else:
            if not args.c.exists():
                print(f"Config at {args.c} doesn't exist", file=sys.stderr)
                sys.exit(1)
            else:
                try:
                    config = parse_config_file(args.c)
                    set_logger(config)
                    logger.info("Parsed config successfully")
                    trio.run(start, config, args.d, args.r)
                except Exception as e:
                    logger.error(f"Got error {e} while parsing config at {args.c}")
                    sys.exit(1)


if __name__ == "__main__":
    main()
