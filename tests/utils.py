import asyncio


def timeout(secs: float):
    def wrapper(func):
        async def run(*args, **kwargs):
            return await asyncio.wait_for(func(*args, **kwargs), timeout=secs)

        return run

    return wrapper
