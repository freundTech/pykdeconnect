import argparse
import asyncio
import logging
from pathlib import Path

from .client import KdeConnectClient
from .const import KdeConnectDeviceType
from .devices import KdeConnectDevice
from .helpers import keyboard_interrupt
from .plugin_registry import PluginRegistry
from .storage import FileStorage


async def main() -> None:
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="KDEConnect implementation in python")
    parser.add_argument("--name", default="PyKDEConnect", help="The name of the KDEConnect client")
    parser.add_argument("--type", choices=[t.value for t in KdeConnectDeviceType], default="phone",
                        help="The type of the client")

    args = parser.parse_args()
    client = KdeConnectClient(args.name, KdeConnectDeviceType(args.type),
                              FileStorage(Path.home() / ".config" / "pykdeconnect"),
                              PluginRegistry())
    client.set_pairing_callback(on_pairing_request)

    await client.start()
    await keyboard_interrupt()
    await client.stop()


async def on_pairing_request(_: KdeConnectDevice) -> bool:
    return True


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
