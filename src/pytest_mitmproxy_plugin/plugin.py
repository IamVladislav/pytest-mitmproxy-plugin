from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from typing import Any

import pytest

from pytest_mitmproxy_plugin.mitm_manager import MitmManager, MitmMode


def pytest_addoption(parser: Any) -> None:
    parser.addoption(
        "--proxy-mode",
        default=None,
        type=MitmMode,
        help=f'MITM proxy mode - {", ".join(list(MitmMode))}',
        choices=list(MitmMode),
    )
    parser.addoption("--proxy-host", default=None, type=str, help="MITM proxy host")
    parser.addoption("--proxy-port", default=None, type=int, help="MITM proxy port")
    parser.addoption(
        "--proxy-log-level",
        default=None,
        type=str,
        help="MITM proxy log level",
        choices=logging.getLevelNamesMapping().keys(),
    )
    parser.addoption("--proxy-log-dir-path", default=None, help="Folder-destination for logs")


@pytest.fixture(scope="session")
def mitm_manager_session(request: pytest.FixtureRequest) -> Iterator[MitmManager]:
    config_path = request.config.rootpath.joinpath("pyproject.toml")
    if config_path.exists():
        with config_path.open("rb") as config_file:
            parsed_config = tomllib.load(config_file)
        proxy_config = parsed_config.get("mitmproxy-plugin", {})
    else:
        proxy_config = {}

    mode = (
        _mode
        if (_mode := request.config.getoption("--proxy-mode")) is not None
        else (MitmMode(_mode) if (_mode := proxy_config.get("mode")) is not None else MitmMode.SOCKS5)
    )
    listen_host = (
        _host
        if (_host := request.config.getoption("--proxy-host")) is not None
        else (_host if (_host := proxy_config.get("host")) is not None else "127.0.0.1")
    )
    listen_port = (
        _port
        if (_port := request.config.getoption("--proxy-port")) is not None
        else (_port if (_port := proxy_config.get("port")) is not None else 0)
    )
    log_level = logging.getLevelNamesMapping()[
        (
            _log_level
            if (_log_level := request.config.getoption("--proxy-log-level")) is not None
            else (_log_level if (_log_level := proxy_config.get("log_level")) is not None else "INFO")
        )
    ]

    if (raw_path := request.config.getoption("--proxy-log-dir-path")) is not None or (
        raw_path := proxy_config.get("log_dir_path")
    ) is not None:
        if not (path := Path(raw_path)).exists():
            path.mkdir(parents=True, exist_ok=True)
        log_dir_path = path
    else:
        log_dir_path = None

    mitm_instance = MitmManager(
        mode=mode,
        listen_host=listen_host,
        listen_port=listen_port,
        log_level=log_level,
        log_dir_path=log_dir_path,
    )
    mitm_instance.start()
    yield mitm_instance
    mitm_instance.shutdown()


@pytest.fixture
def mitm_manager(mitm_manager_session: MitmManager) -> Iterator[MitmManager]:
    yield mitm_manager_session
    mitm_manager_session.delete_all_addons()
