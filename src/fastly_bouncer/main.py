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
from pycrowdsec.client import StreamClient

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
    sender_chan,
) -> ACLCollection:

    acl_count = ceil(service_cfg.max_items / ACL_CAPACITY)
    acl_collection = ACLCollection(
        api=fastly_api,
        service_id=service_cfg.id,
        version=service_version,
        action=action,
        state=set(),
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
    async with sender_chan:
        await sender_chan.send(acl_collection)


async def setup_service(
    service_cfg: FastlyServiceConfig,
    fastly_api: FastlyAPI,
    cleanup_mode: bool,
    sender_chan: trio.MemorySendChannel,
):
    if service_cfg.clone_reference_version or (
        cleanup_mode
        and (
            await fastly_api.is_service_version_locked(
                service_cfg.id, service_cfg.reference_version
            )
        )
    ):
        comment = None
        if cleanup_mode:
            comment = "Clone cleaned from CrowdSec resources"
        version = await fastly_api.clone_version_for_service_from_given_version(
            service_cfg.id, service_cfg.reference_version, comment
        )
        logger.info(
            with_suffix(
                f"new version {version} for service created",
                service_id=service_cfg.id,
            )
        )
    else:
        version = service_cfg.reference_version
        logger.info(
            with_suffix(
                f"using existing version {service_cfg.reference_version}",
                service_id=service_cfg.id,
            )
        )

    logger.info(
        with_suffix(
            f"cleaning existing crowdsec resources (if any)",
            service_id=service_cfg.id,
            version=version,
        )
    )

    await fastly_api.clear_crowdsec_resources(service_cfg.id, version)
    if cleanup_mode:
        sender_chan.close()
        return

    logger.info(
        with_suffix(
            f"cleaned existing crowdsec resources (if any)",
            service_id=service_cfg.id,
            version=version,
        )
    )

    acl_collection_by_action = {}
    for action in SUPPORTED_ACTIONS:
        sender, receiver = trio.open_memory_channel(0)
        async with trio.open_nursery() as n:
            async with sender:
                n.start_soon(
                    setup_action_for_service,
                    fastly_api,
                    action,
                    service_cfg,
                    version,
                    sender.clone(),
                )

            async with receiver:
                async for acl_collection in receiver:
                    acl_collection_by_action[acl_collection.action] = acl_collection

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


async def setup_account(account_cfg: FastlyAccountConfig, cleanup: bool, sender_chan):
    fastly_api = FastlyAPI(account_cfg.account_token)
    new_services = []
    sender, receiver = trio.open_memory_channel(0)
    async with trio.open_nursery() as n:
        async with sender:
            for cfg in account_cfg.services:
                n.start_soon(setup_service, cfg, fastly_api, cleanup, sender.clone())

        async with receiver:
            async for service in receiver:
                new_services.append(service)

    async with sender_chan:
        await sender_chan.send(new_services)


async def setup_fastly_infra(config: Config, cleanup_mode):
    p = Path(config.cache_path)
    if p.exists():
        logger.info("cache file exists")
        async with await trio.open_file(config.cache_path) as f:
            s = await f.read()
            if not s:
                logger.warning(f"cache file at {config.cache_path} is empty")
            else:
                cache = json.loads(s)
                services = list(map(Service.from_jsonable_dict, cache["service_states"]))
                logger.info(f"loaded exisitng infra using cache")
                if not cleanup_mode:
                    return services
    else:
        p.parent.mkdir(exist_ok=True, parents=True)

    if cleanup_mode:
        logger.info("cleaning fastly infra")
    else:
        logger.info("setting up fastly infra")

    services = []
    sender, receiver = trio.open_memory_channel(0)
    async with trio.open_nursery() as n:
        async with sender:
            for cfg in config.fastly_account_configs:
                n.start_soon(setup_account, cfg, cleanup_mode, sender.clone())

        async for service_chunk in receiver:
            services.extend(service_chunk)

    return services


def set_logger(config: Config):
    global logger
    list(map(logger.removeHandler, logger.handlers))
    logger.setLevel(config.get_log_level())
    if config.log_mode == "stdout":
        handler = logging.StreamHandler(sys.stdout)
    elif config.log_mode == "stderr":
        handler = logging.StreamHandler(sys.stderr)
    elif config.log_mode == "file":
        handler = RotatingFileHandler(config.log_file, mode="a+")
    formatter = CustomFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info(f"Starting fastly-bouncer-v{VERSION}")


async def run(config: Config, services: List[Service]):
    global VERSION
    crowdsec_client = StreamClient(
        lapi_url=config.crowdsec_config.lapi_url,
        api_key=config.crowdsec_config.lapi_key,
        scopes=["ip", "range", "country", "as"],
        interval=config.update_frequency,
    )
    crowdsec_client.run()
    await trio.sleep(2)  # Wait for initial polling by bouncer, so we start with a hydrated state
    if not crowdsec_client.is_running():
        return
    previous_states = {}
    while True and not exiting:
        new_state = crowdsec_client.get_current_decisions()

        async with trio.open_nursery() as n:
            for s in services:
                n.start_soon(s.transform_state, new_state)

        new_states = list(map(lambda service: service.as_jsonable_dict(), services))
        if new_states != previous_states:
            logger.debug("updating cache")
            new_cache = {"service_states": new_states, "bouncer_version": VERSION}
            async with await trio.open_file(config.cache_path, "w") as f:
                await f.write(json.dumps(new_cache, indent=4))
            logger.debug("done updating cache")
            previous_states = new_states

        if exiting:
            return

        await trio.sleep(config.update_frequency)


async def start(config: Config, cleanup_mode):
    global services
    services = await setup_fastly_infra(config, cleanup_mode)
    if cleanup_mode:
        if Path(config.cache_path).exists():
            logger.info("cleaning cache")
            with open(config.cache_path, "w") as f:
                pass
        return

    await run(config, services)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "-c",
        type=Path,
        help="Path to configuration file.",
        default=Path("/etc/crowdsec/bouncers/crowdsec-fastly-bouncer.yaml"),
    )
    arg_parser.add_argument("-d", help="Whether to cleanup resources.", action="store_true")
    arg_parser.add_argument("-g", type=str, help="Comma separated tokens to generate config for.")
    arg_parser.add_argument("-o", type=str, help="Path to file to output the generated config.")
    arg_parser.add_help = True
    args = arg_parser.parse_args()
    if not args.c or not args.c.exists():
        if not args.c:
            print("config file not provided", file=sys.stderr)
        else:
            print(f"config at {args.c} doesn't exist", file=sys.stderr)
        if args.g:
            gc = trio.run(ConfigGenerator().generate_config, args.g)
            print_config(gc, args.o)
            sys.exit(0)

        arg_parser.print_help()
        sys.exit(1)
    try:
        config = parse_config_file(args.c)
        if args.d or args.c:  # We want to display this to stderr
            config.log_mode = "stderr"
        set_logger(config)
    except Exception as e:
        logger.error(f"got error {e} while parsing config at {args.c}")
        sys.exit(1)

    if args.g:
        gc = trio.run(ConfigGenerator().generate_config, args.g, config)
        print_config(gc, args.o)
        sys.exit(0)

    logger.info("parsed config successfully")
    trio.run(start, config, args.d)


if __name__ == "__main__":
    main()
