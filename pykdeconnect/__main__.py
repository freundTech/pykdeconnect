import argparse
import asyncio
from pathlib import Path

from .helpers import keyboard_interrupt
from .client import KdeConnectClient, KdeConnectDeviceType, KdeConnectConfig
from .devices import KdeConnectDevice


async def main():
    parser = argparse.ArgumentParser(description="KDEConnect implementation in python")
    parser.add_argument("--name", default="PyKDEConnect", help="The name of the KDEConnect client")
    parser.add_argument("--type", choices=[t.value for t in KdeConnectDeviceType], default="phone",
                        help="The type of the client")

    args = parser.parse_args()
    client = KdeConnectClient(args.name, KdeConnectDeviceType(args.type),
                              KdeConnectConfig(Path.home() / ".config" / "pykdeconnect"))
    client.set_pairing_callback(on_pairing_request)

    await client.start()
    await keyboard_interrupt()


async def on_pairing_request(device: KdeConnectDevice):
    #print(f'"{device.device_name}" wants to pair. Rejecting.')
    return True


if __name__ == '__main__':
    asyncio.run(main())
