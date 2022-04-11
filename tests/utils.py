import asyncio
import functools
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import MagicMock, patch


def timeout(secs: float):
    def wrapper(func):
        async def run(*args, **kwargs):
            return await asyncio.wait_for(func(*args, **kwargs), timeout=secs)

        return run

    return wrapper


_SENTINEL = object()
_TIMESTAMP = 1591524000


def get_faketime():
    return _TIMESTAMP * 1000


@contextmanager
def _patch_timestamp():
    with patch("pykdeconnect.helpers.datetime") as mocktime:
        mocktime.now = MagicMock(return_value=datetime.fromtimestamp(_TIMESTAMP))
        yield


def patch_timestamp(func=_SENTINEL):
    if func is _SENTINEL:
        return patch_timestamp

    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            with _patch_timestamp():
                await func(*args, **kwargs)

    else:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with _patch_timestamp():
                func(*args, **kwargs)

    return wrapper
