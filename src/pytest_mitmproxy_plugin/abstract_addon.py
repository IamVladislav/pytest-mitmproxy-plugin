from __future__ import annotations

import json
import re
from contextlib import contextmanager
from enum import StrEnum
from typing import Any, cast, TYPE_CHECKING
from xml.etree import ElementTree

from mitmproxy.http import Response

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable
    from xml.etree.ElementTree import Element

    from mitmproxy.http import HTTPFlow


class AbstractAddon:
    def __repr__(self) -> str:
        return self.__class__.__name__


class AbsentRequestTextError(Exception):
    pass


class AbsentResponseError(Exception):
    pass


class AbsentResponseTextError(Exception):
    pass


class NoSuchElementInTreeError(Exception):
    pass


class HTTPRequestMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    CONNECT = "CONNECT"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    PATCH = "PATCH"


class HTTPAddonHelper(AbstractAddon):
    @staticmethod
    def _does_path_match(flow: HTTPFlow, pattern: str | re.Pattern[str]) -> bool:
        return re.match(pattern, flow.request.path) is not None

    @staticmethod
    def _does_path_contain(flow: HTTPFlow, pattern: str | re.Pattern[str]) -> bool:
        return re.search(pattern, flow.request.path) is not None

    @staticmethod
    def _does_url_contain(flow: HTTPFlow, pattern: str | re.Pattern[str]) -> bool:
        return re.search(pattern, flow.request.pretty_url) is not None

    @staticmethod
    def _is_request_type(flow: HTTPFlow, request_method: HTTPRequestMethod) -> bool:
        return flow.request.method == request_method

    @staticmethod
    def _get_request_text(flow: HTTPFlow) -> str:
        if (request_text := flow.request.text) is None:
            message = f"No request text for request with path: '{flow.request.path}'"
            raise AbsentRequestTextError(message)
        return request_text

    @classmethod
    def _get_request_json(cls, flow: HTTPFlow) -> Any:
        return json.loads(cls._get_request_text(flow))

    @staticmethod
    def _set_request_json(flow: HTTPFlow, json_data: Any) -> None:
        flow.request.text = json.dumps(json_data)

    @classmethod
    @contextmanager
    def _json_request_context_manager(cls, flow: HTTPFlow) -> Generator[Any, None, None]:
        data = cls._get_request_json(flow)
        yield data
        cls._set_request_json(flow, data)

    @staticmethod
    def _remove_request_cookies(flow: HTTPFlow, cookie_names: Iterable[str]) -> None:
        for cookie_name in cookie_names:
            if cookie_name in flow.request.cookies:
                flow.request.cookies.pop(cookie_name)

    @staticmethod
    def _is_response_present(flow: HTTPFlow) -> bool:
        return flow.response is not None

    @classmethod
    def _get_response(cls, flow: HTTPFlow) -> Response:
        if cls._is_response_present(flow):
            return cast(Response, flow.response)
        message = f"No response for request with path: '{flow.request.path}'"
        raise AbsentResponseError(message)

    @classmethod
    def _get_response_text(cls, flow: HTTPFlow) -> str:
        if (response_text := cls._get_response(flow).text) is None:
            message = f"No response text received for request with path: '{flow.request.path}'"
            raise AbsentResponseTextError(message)
        return response_text

    @classmethod
    def _set_response_text(cls, flow: HTTPFlow, text: str) -> None:
        cast(Response, flow.response).text = text

    @classmethod
    def _get_response_json(cls, flow: HTTPFlow) -> Any:
        return json.loads(cls._get_response_text(flow))

    @classmethod
    def _set_response_json(cls, flow: HTTPFlow, json_data: Any) -> None:
        cls._set_response_text(flow, json.dumps(json_data))

    @classmethod
    @contextmanager
    def _json_response_context_manager(cls, flow: HTTPFlow) -> Generator[Any, None, None]:
        data = cls._get_response_json(flow)
        yield data
        cls._set_response_json(flow, data)

    @classmethod
    def _replace_in_response_text(cls, flow: HTTPFlow, pattern: str | re.Pattern[str], replacement: str) -> None:
        cls._set_response_text(flow, re.sub(pattern, replacement, cls._get_response_text(flow)))

    @classmethod
    def _does_request_body_contain(cls, flow: HTTPFlow, pattern: str | re.Pattern[str]) -> bool:
        return re.search(pattern, cls._get_request_text(flow)) is not None

    @classmethod
    def _get_response_xml(cls, flow: HTTPFlow) -> Element:
        return ElementTree.fromstring(cls._get_response_text(flow))

    @classmethod
    def _set_response_xml(cls, flow: HTTPFlow, tree: Element) -> None:
        cls._get_response(flow).text = ElementTree.tostring(tree, encoding="utf8", method="xml").decode("utf-8")

    @classmethod
    @contextmanager
    def _xml_response_context_manager(cls, flow: HTTPFlow) -> Generator[Element, None, None]:
        data = cls._get_response_xml(flow)
        yield data
        cls._set_response_xml(flow, data)

    @staticmethod
    def _get_xml_element_from_xml_tree(tree: Element, element_path: str) -> Element:
        element = tree.find(element_path)
        if element is None:
            message = f"There is no an XML element with path: {element_path}"
            raise NoSuchElementInTreeError(message)
        return element

    @classmethod
    def _replace_element_value_in_xml_response(cls, *, flow: HTTPFlow, element_path: str, value: str) -> None:
        with cls._xml_response_context_manager(flow) as tree:
            cls._get_xml_element_from_xml_tree(tree, element_path).text = value

    @classmethod
    def _remove_fields_from_xml_response(
        cls, *, flow: HTTPFlow, main_element_path: str, elements_to_remove_path: Iterable[str]
    ) -> None:
        with cls._xml_response_context_manager(flow) as tree:
            main_element = cls._get_xml_element_from_xml_tree(tree, main_element_path)
            for element_to_remove_path in elements_to_remove_path:
                element_to_remove = main_element.find(element_to_remove_path)
                if element_to_remove is None:
                    continue
                main_element.remove(element_to_remove)

    @classmethod
    def _replace_all_xml_values_in_xml_response(
        cls,
        *,
        flow: HTTPFlow,
        element_path: str,
        value: str,
    ) -> None:
        with cls._xml_response_context_manager(flow) as tree:
            for element in tree.findall(element_path):
                element.text = value

    @classmethod
    def _replace_element_attribute_in_xml_response(
        cls, *, flow: HTTPFlow, xml_element_path: str, attribute: str, new_value: str
    ) -> None:
        with cls._xml_response_context_manager(flow) as tree:
            cls._get_xml_element_from_xml_tree(tree, xml_element_path).set(attribute, new_value)

    @classmethod
    def _update_element_tree_in_xml_response(
        cls, *, flow: HTTPFlow, element_path: str, new_tree: Element, replace_whole_tree: bool
    ) -> None:
        with cls._xml_response_context_manager(flow) as tree:
            element = cls._get_xml_element_from_xml_tree(tree, element_path)
            if replace_whole_tree:
                element.clear()
            element.append(new_tree)
