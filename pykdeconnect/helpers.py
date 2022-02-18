import asyncio
from datetime import datetime, timezone


def get_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


async def keyboard_interrupt():
    while True:
        try:
            await asyncio.sleep(1)
        except KeyboardInterrupt:
            raise SystemExit
