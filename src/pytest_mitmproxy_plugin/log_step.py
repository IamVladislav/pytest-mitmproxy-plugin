from __future__ import annotations

from typing import Any, ParamSpec, TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")


class step:  # noqa: N801
    def __init__(self, *args: Any, **_: Any) -> None:
        self.message = args[0] if len(args) > 0 and isinstance(args[0], str) else None

    def __enter__(self) -> None:
        if self.message is not None:
            logger.info(self.message)

    def __exit__(self, *args: object) -> None:
        pass

    def __call__(self, function: Callable[P, T]) -> Callable[P, T]:
        if self.message is not None:

            def logged_func(*args: Any, **kwargs: Any) -> T:
                logger.info(self.message)
                return function(*args, **kwargs)

            return logged_func
        return function
