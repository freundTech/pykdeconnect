import asyncio
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


def patch_timestamp(func=_SENTINEL):
    if func is _SENTINEL:
        return patch_timestamp

    def run(*args, **kwargs):
        with patch("pykdeconnect.helpers.datetime") as mocktime:
            mocktime.now = MagicMock(return_value=datetime.fromtimestamp(_TIMESTAMP))
            func(*args, **kwargs)

    return run
