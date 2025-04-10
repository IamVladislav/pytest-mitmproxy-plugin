from __future__ import annotations

from typing import TYPE_CHECKING

from _pytest.config import ExitCode

if TYPE_CHECKING:
    from _pytest.pytester import Pytester

test_pattern = """
        import datetime
        import uuid
    
        import requests
        
        from mitmproxy.http import HTTPFlow, Response
        from pytest_mitmproxy_plugin.abstract_addon import AbstractAddon
        from pytest_mitmproxy_plugin.mitm_manager import MitmManager
        
        def test_a(mitm_manager: MitmManager):
            class SimpleAddon(AbstractAddon):
                def __init__(self, response_text: str):
                    self.response_text = response_text
        
                def request(self, flow: HTTPFlow):
                    flow.intercept()
                    resp = Response(
                        http_version=b"HTTP/2.0",
                        status_code=200,
                        reason=b"OK",
                        headers=flow.request.headers,
                        content=self.response_text.encode(),
                        trailers=None,
                        timestamp_start=datetime.datetime.now().timestamp(),
                        timestamp_end=None,
                    )
                    flow.response = resp
                    flow.resume()
        
            response_text = str(uuid.uuid4())
        
            mitm_manager.add_addon(SimpleAddon(response_text))
        
            response = requests.get(
                f"http://google.com",
                proxies={
                    "http": f"socks5h://{mitm_manager.host}:{mitm_manager.port}",
                },
            )
            assert response.text == response_text, f"Unexpected response, {response.content}"
        """

test_failure_pattern = """
        from pytest_mitmproxy_plugin.mitm_manager import MitmManager

        def test_a(mitm_manager: MitmManager):
            raise AssertionError
        """


def test_fixture_all_default(pytester: Pytester) -> None:
    pytester.makepyfile(test_pattern)

    result = pytester.runpytest()
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_port_overridden_by_flag(pytester: Pytester) -> None:
    port = str(10028)
    pytester.makepyfile(test_pattern.replace("{mitm_manager.port}", port))

    result = pytester.runpytest("--proxy-port", port)
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_port_overridden_by_config(pytester: Pytester) -> None:
    port = str(10029)

    pytester.makepyprojecttoml(f"""
    [mitmproxy-plugin]
    port = {port}
    """)
    pytester.makepyfile(test_pattern.replace("{mitm_manager.port}", port))

    result = pytester.runpytest()
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_port_overridden_by_flag_and_config(pytester: Pytester) -> None:
    port = str(10030)
    c_port = str(10031)

    pytester.makepyprojecttoml(f"""
    [mitmproxy-plugin]
    port = {c_port}
    """)
    pytester.makepyfile(test_pattern.replace("{mitm_manager.port}", port))

    result = pytester.runpytest("--proxy-port", port)
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_logger(pytester: Pytester) -> None:
    log_line = "INFO     pytest_mitmproxy_plugin*"
    pytester.makepyfile(test_failure_pattern)

    result = pytester.runpytest("--log-level=INFO")
    result.stdout.fnmatch_lines(log_line)


def test_fixture_logger_overridden_by_flag(pytester: Pytester) -> None:
    log_line = "INFO     pytest_mitmproxy_plugin*"
    pytester.makepyfile(test_failure_pattern)

    result = pytester.runpytest("--log-level=INFO", "--proxy-log-level", "WARNING")
    result.stdout.no_fnmatch_line(log_line)


def test_fixture_logger_overridden_config(pytester: Pytester) -> None:
    log_line = "INFO     pytest_mitmproxy_plugin*"
    pytester.makepyfile(test_failure_pattern)

    pytester.makepyprojecttoml("""
    [mitmproxy-plugin]
    log_level = "WARNING"
    """)

    result = pytester.runpytest("--log-level=INFO")
    result.stdout.no_fnmatch_line(log_line)


def test_fixture_logger_overridden_by_flag_and_config(pytester: Pytester) -> None:
    log_line = "INFO     pytest_mitmproxy_plugin*"
    pytester.makepyfile(test_failure_pattern)

    pytester.makepyprojecttoml("""
    [mitmproxy-plugin]
    log_level = "DEBUG"
    """)

    result = pytester.runpytest("--log-level=INFO", "--proxy-log-level", "WARNING")
    result.stdout.no_fnmatch_line(log_line)


def test_fixture_mode_overridden_by_flag(pytester: Pytester) -> None:
    pytester.makepyfile(test_pattern.replace("socks5h", "http"))

    result = pytester.runpytest("--proxy-mode", "regular")
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_mode_overridden_by_config(pytester: Pytester) -> None:
    pytester.makepyfile(test_pattern.replace("socks5h", "http"))

    pytester.makepyprojecttoml("""
    [mitmproxy-plugin]
    mode = "regular"
    """)

    result = pytester.runpytest()
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"


def test_fixture_mode_overridden_by_flag_and_config(pytester: Pytester) -> None:
    pytester.makepyfile(test_pattern.replace("socks5h", "http"))

    pytester.makepyprojecttoml("""
    [mitmproxy-plugin]
    mode = "socks5"
    """)

    result = pytester.runpytest("--proxy-mode", "regular")
    assert result.ret == ExitCode.OK, "Unexpected internal test failure"
