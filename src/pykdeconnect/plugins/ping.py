from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from typing_extensions import TypedDict

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.helpers import get_timestamp
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin
from pykdeconnect.vol_extra import TypedDictVerifier

PingCallback = Callable[[], Awaitable[None]]


class PingPayloadBody(TypedDict):
    pass


class PingPayload(Payload):
    body: PingPayloadBody


class PingReceiverPlugin(Plugin):
    _payload_verifier: TypedDictVerifier[PingPayload]

    _ping_callbacks: set[PingCallback]

    def __init__(self, device: KdeConnectDevice):
        super().__init__(device)
        self._payload_verifier = TypedDictVerifier[PingPayload]()
        self._ping_callbacks = set()

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> PingReceiverPlugin:
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> set[str]:
        return {"kdeconnect.ping"}

    @classmethod
    def get_outgoing_payload_types(cls) -> set[str]:
        return set()

    async def handle_payload(self, payload: Payload) -> None:
        self._payload_verifier.verify(payload)
        callbacks = {callback() for callback in self._ping_callbacks}

        await asyncio.gather(*callbacks)

    def register_ping_callback(self, callback: PingCallback) -> None:
        self._ping_callbacks.add(callback)

    def unregister_ping_callback(self, callback: PingCallback) -> None:
        self._ping_callbacks.remove(callback)


class PingSenderPlugin(Plugin):
    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> PingSenderPlugin:
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> set[str]:
        return set()

    @classmethod
    def get_outgoing_payload_types(cls) -> set[str]:
        return {"kdeconnect.ping"}

    async def handle_payload(self, payload: Payload) -> None:
        assert False

    def send_ping(self) -> None:
        payload: PingPayload = {
            "id": get_timestamp(),
            "type": "kdeconnect.ping",
            "body": {}
        }
        self.device.send_payload(payload)
