from __future__ import annotations

import asyncio
import logging
from asyncio import Future
from typing import Awaitable, Callable, Optional, TypeVar

from cryptography.x509 import Certificate

from .const import KdeConnectDeviceType, PairingResult
from .exceptions import NotConnectedError
from .helpers import async_timeout
from .payloads import IdentityPayload
from .plugin import Plugin
from .protocols import DeviceProtocol

P = TypeVar('P', bound=Plugin)


logger = logging.getLogger(__name__)


ConnectionCallback = Callable[[], Awaitable[None]]


class KdeConnectDevice:
    device_name: str
    device_id: str
    device_type: KdeConnectDeviceType
    incoming_capabilities: set[str]
    outgoing_capabilities: set[str]

    certificate: Optional[Certificate]

    protocol: Optional[DeviceProtocol]
    is_connected: bool = False

    wants_pairing: bool = False
    pairing_future: Optional[Future[PairingResult]] = None

    device_connected_callbacks: set[ConnectionCallback]
    device_disconnected_callbacks: set[ConnectionCallback]

    def __init__(
            self,
            device_name: str,
            device_id: str,
            device_type: KdeConnectDeviceType,
            incoming_capabilities: set[str],
            outgoing_capabilities: set[str],
            cert: Optional[Certificate]
    ) -> None:
        self.device_name = device_name
        self.device_id = device_id
        self.device_type = device_type
        self.incoming_capabilities = set(incoming_capabilities)
        self.outgoing_capabilities = set(outgoing_capabilities)
        self.certificate = cert

        self.protocol = None

        self.device_connected_callbacks = set()
        self.device_disconnected_callbacks = set()

    async def pair(self) -> PairingResult:
        if self.is_paired:
            return PairingResult.ACCEPTED
        if self.pairing_future is None:
            self.request_pair()
            loop = asyncio.get_running_loop()
            self.pairing_future = loop.create_future()
        asyncio.create_task(async_timeout(self.pairing_future, PairingResult.TIMEOUT, 20))
        result = await self.pairing_future
        self.pairing_future = None
        return result

    def request_pair(self) -> None:
        if self.protocol is None:
            raise NotConnectedError()
        self.protocol.send_pairing_payload(True)
        self.wants_pairing = True

    def unpair(self) -> None:
        if self.protocol is None:
            raise NotConnectedError()
        self.protocol.send_pairing_payload(False)
        self.set_unpaired()

    def confirm_pair(self) -> None:
        if self.protocol is None:
            raise NotConnectedError()
        self.protocol.send_pairing_payload(True)
        self.set_paired()

    def reject_pair(self) -> None:
        if self.protocol is None:
            raise NotConnectedError()
        self.protocol.send_pairing_payload(False)

    def set_paired(self, certificate: Certificate | None = None) -> None:
        if certificate is None:
            if self.protocol is None:
                raise NotConnectedError()
            certificate = self.protocol.get_certificate()

        self.certificate = certificate
        self.wants_pairing = False
        logger.debug('Paired device "%s"', self.device_name)
        if self.pairing_future is not None:
            self.pairing_future.set_result(PairingResult.ACCEPTED)

    def set_unpaired(self) -> None:
        self.certificate = None
        self.wants_pairing = False
        logger.debug('Unpaired device "%s"', self.device_name)
        if self.pairing_future is not None:
            self.pairing_future.set_result(PairingResult.REJECTED)

    async def close_connection(self) -> None:
        if self.protocol is None:
            raise NotConnectedError()
        await self.protocol.close_connection()

    @property
    def is_paired(self) -> bool:
        return self.certificate is not None

    @classmethod
    def from_payload(cls, payload: IdentityPayload) -> KdeConnectDevice:
        # TODO: Change return type to Self once mypy supports it
        return cls(
            payload["body"]["deviceName"],
            payload["body"]["deviceId"],
            KdeConnectDeviceType(payload["body"]["deviceType"]),
            set(payload["body"]["incomingCapabilities"]),
            set(payload["body"]["outgoingCapabilities"]),
            None
        )

    def update_from_payload(self, payload: IdentityPayload) -> None:
        if self.device_id != payload["body"]["deviceId"]:
            raise ValueError("Payload device id doesn't match device id")
        self.device_name = payload["body"]["deviceName"]
        self.device_type = KdeConnectDeviceType(payload["body"]["deviceType"])
        self.incoming_capabilities = set(payload["body"]["incomingCapabilities"])
        self.outgoing_capabilities = set(payload["body"]["outgoingCapabilities"])

    async def device_connected(self) -> None:
        await asyncio.gather(*(callback() for callback in self.device_connected_callbacks))

    async def device_disconnected(self) -> None:
        self.is_connected = False
        await asyncio.gather(*(callback() for callback in self.device_disconnected_callbacks))

    def register_device_connected_callback(self, callback: ConnectionCallback) -> None:
        self.device_connected_callbacks.add(callback)

    def unregister_device_connected_callback(self, callback: ConnectionCallback) -> None:
        self.device_connected_callbacks.remove(callback)

    def register_device_disconnected_callback(self, callback: ConnectionCallback) -> None:
        self.device_connected_callbacks.add(callback)

    def unregister_device_disconnected_callback(self, callback: ConnectionCallback) -> None:
        self.device_connected_callbacks.remove(callback)
