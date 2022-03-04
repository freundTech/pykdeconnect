from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional, Set

from .devices import KdeConnectDevice
from .storage import AbstractStorage

logger = logging.getLogger(__name__)


PairingCallback = Callable[[KdeConnectDevice], Awaitable[bool]]
DeviceCallback = Callable[[KdeConnectDevice], Awaitable[None]]


class DeviceManager:
    connected_devices: dict[str, KdeConnectDevice]

    _storage: AbstractStorage

    _pairing_callback: Optional[PairingCallback] = None

    _device_connected_callbacks: Set[DeviceCallback]
    _device_disconnected_callbacks: Set[DeviceCallback]

    def __init__(self, storage: AbstractStorage) -> None:
        self._storage = storage

        self.connected_devices = {}

        self._device_connected_callbacks = set()
        self._device_disconnected_callbacks = set()

    def get_device(self, device_id: str) -> Optional[KdeConnectDevice]:
        if device_id in self.connected_devices:
            return self.connected_devices[device_id]

        return self._storage.load_device(device_id)

    async def disconnect_all(self) -> None:
        await asyncio.gather(
            *(device.close_connection() for device in self.connected_devices.values())
        )

    def set_pairing_callback(self, callback: PairingCallback) -> None:
        self._pairing_callback = callback

    async def on_pairing_request(self, device: KdeConnectDevice) -> None:
        if self._pairing_callback is not None:
            result = await self._pairing_callback(device)
            if result:
                device.confirm_pair()
                self._storage.store_device(device)
            else:
                device.reject_pair()
        else:
            logger.warning(
                '"%s" requested pairing, but no pairing callback was set. Rejecting.',
                device.device_name
            )
            device.unpair()

    def unpair(self, device: KdeConnectDevice) -> None:
        self._storage.remove_device(device)
        device.set_unpaired()

    async def device_connected(self, device: KdeConnectDevice) -> None:
        callbacks = [callback(device) for callback in self._device_connected_callbacks]
        callbacks.append(device.device_connected())
        await asyncio.gather(*callbacks)

    async def device_disconnected(self, device: KdeConnectDevice) -> None:
        callbacks = [callback(device) for callback in self._device_disconnected_callbacks]
        callbacks.append(device.device_disconnected())
        await asyncio.gather(*callbacks)

    def register_device_connected_callback(self, callback: DeviceCallback) -> None:
        self._device_connected_callbacks.add(callback)

    def unregister_device_connected_callback(self, callback: DeviceCallback) -> None:
        self._device_connected_callbacks.remove(callback)

    def register_device_disconnected_callback(self, callback: DeviceCallback) -> None:
        self._device_disconnected_callbacks.add(callback)

    def unregister_device_disconnected_callback(self, callback: DeviceCallback) -> None:
        self._device_disconnected_callbacks.remove(callback)
