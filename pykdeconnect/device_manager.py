from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, ValuesView

from .devices import KdeConnectDevice
from .storage import AbstractStorage

logger = logging.getLogger(__name__)


PairingCallback = Callable[[KdeConnectDevice], Awaitable[bool]]
DeviceCallback = Callable[[KdeConnectDevice], Awaitable[None]]


class DeviceManager:
    _connected_devices: dict[str, KdeConnectDevice]

    _storage: AbstractStorage

    _pairing_callback: PairingCallback | None = None

    _device_connected_callbacks: set[DeviceCallback]
    _device_disconnected_callbacks: set[DeviceCallback]

    def __init__(self, storage: AbstractStorage) -> None:
        self._storage = storage

        self._connected_devices = {}

        self._device_connected_callbacks = set()
        self._device_disconnected_callbacks = set()

    def add_device(self, device: KdeConnectDevice) -> None:
        self._connected_devices[device.device_id] = device

    def remove_device(self, device: KdeConnectDevice) -> None:
        del self._connected_devices[device.device_id]

    def get_device(self, device_id: str) -> KdeConnectDevice | None:
        if device_id in self._connected_devices:
            return self._connected_devices[device_id]

        return self._storage.load_device(device_id)

    def get_devices(self) -> ValuesView[KdeConnectDevice]:
        return self._connected_devices.values()

    async def disconnect_all(self) -> None:
        await asyncio.gather(
            *(device.close_connection() for device in self._connected_devices.values())
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
            device.reject_pair()

    def unpair(self, device: KdeConnectDevice) -> None:
        self._storage.remove_device(device)
        device.set_unpaired()

    async def device_connected(self, device: KdeConnectDevice) -> None:
        callbacks = {callback(device) for callback in self._device_connected_callbacks}
        callbacks.add(device.device_connected())
        await asyncio.gather(*callbacks)

    async def device_disconnected(self, device: KdeConnectDevice) -> None:
        callbacks = {callback(device) for callback in self._device_disconnected_callbacks}
        callbacks.add(device.device_disconnected())
        await asyncio.gather(*callbacks)

    def register_device_connected_callback(self, callback: DeviceCallback) -> None:
        self._device_connected_callbacks.add(callback)

    def unregister_device_connected_callback(self, callback: DeviceCallback) -> None:
        self._device_connected_callbacks.remove(callback)

    def register_device_disconnected_callback(self, callback: DeviceCallback) -> None:
        self._device_disconnected_callbacks.add(callback)

    def unregister_device_disconnected_callback(self, callback: DeviceCallback) -> None:
        self._device_disconnected_callbacks.remove(callback)
