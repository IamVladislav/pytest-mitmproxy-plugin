from __future__ import annotations

import asyncio
import logging
import threading
import time
from enum import StrEnum
from typing import IO, TYPE_CHECKING

from mitmproxy import exceptions, options
from mitmproxy.addons import proxyserver
from mitmproxy.addons.dumper import Dumper
from mitmproxy.tools.dump import DumpMaster

if TYPE_CHECKING:
    from typing import Any

    from pytest_mitmproxy_plugin.abstract_addon import AbstractAddon

try:
    from allure import step

    step_logger: Any | None = None
except ImportError:
    from pytest_mitmproxy_plugin.log_step import logger as step_logger
    from pytest_mitmproxy_plugin.log_step import step

logger = logging.getLogger(__name__)


class MitmMode(StrEnum):
    REGULAR = "regular"
    TRANSPARENT = "transparent"
    SOCKS5 = "socks5"


class MitmManagerServerNotStartedError(Exception):
    pass


class MitmManager(threading.Thread):
    MAX_NUMBER_OF_STARTING_ATTEMPTS = 100

    def __init__(
        self,
        *,
        mode: MitmMode,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        log_level: int = logging.DEBUG,
        log_file: IO[str] | None = None,
    ) -> None:
        threading.Thread.__init__(self, daemon=True)
        self.proxyInstance = self.__create_instance(listen_host, listen_port, mode, log_file)
        self.added_addons: list[type[AbstractAddon] | AbstractAddon] = []
        self.host = listen_host
        self.port = listen_port

        if step_logger is None:
            logger.setLevel(log_level)
        else:
            logger.disabled = True
            step_logger.setLevel(log_level)

    def run(self) -> None:
        asyncio.run(self.proxyInstance.run())

    @step("[Mitm] Start")
    def start(self) -> None:
        logger.info("[Mitm] Start")
        super().start()
        for _ in range(self.MAX_NUMBER_OF_STARTING_ATTEMPTS):
            if self.proxyInstance.addons.get("proxyserver").is_running:
                break
            time.sleep(0.01)
        else:
            raise MitmManagerServerNotStartedError
        self.port = self.proxyInstance.addons.get("proxyserver").listen_addrs()[0][1]

    @staticmethod
    def __create_instance(
        listen_host: str, listen_port: int, mode: MitmMode, log_file: IO[str] | None = None
    ) -> DumpMaster:
        proxy_options = options.Options(
            listen_host=listen_host, listen_port=listen_port, mode=[mode.value], ssl_insecure=True
        )
        dump_master = DumpMaster(proxy_options, asyncio.new_event_loop(), with_termlog=False, with_dumper=False)
        dump_master.addons.add(Dumper(outfile=log_file))
        dump_master.addons.add(proxyserver)
        return dump_master

    @step("[Mitm] Shutdown")
    def shutdown(self) -> None:
        logger.info("[Mitm] Shutdown")
        self.delete_all_addons()
        self.proxyInstance.shutdown()

    def add_addon(self, addon: type[AbstractAddon] | AbstractAddon) -> None:
        with step(f"[Mitm] Adding addon {addon.__class__.__name__}"):
            logger.info("[Mitm] Adding addon %s", addon.__class__.__name__)
            try:
                self.proxyInstance.addons.add(addon)
                self.added_addons.append(addon)
            except exceptions.AddonManagerError:
                logger.exception("[Mitm] Adding addon %s", addon.__class__.__name__)

    @step("[Mitm] Deleting all addons")
    def delete_all_addons(self) -> None:
        logger.info("[Mitm] Deleting all addons")
        for addon in self.added_addons:
            self.delete_addon(addon)

    def delete_addon(self, addon_to_delete: type[AbstractAddon] | AbstractAddon) -> None:
        with step(f"[Mitm] Deleting addon {addon_to_delete.__class__.__name__}"):
            logger.info("[Mitm] Deleting addon %s", addon_to_delete.__class__.__name__)
            self.proxyInstance.addons.remove(addon_to_delete)
            self.added_addons = [addon for addon in self.added_addons if addon is not addon_to_delete]
