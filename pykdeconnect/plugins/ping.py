from __future__ import annotations

from typing import Awaitable, Callable, Set

from typing_extensions import TypedDict

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin
from pykdeconnect.vol_extra import TypedDictVerifier

PingCallback = Callable[[], Awaitable[None]]


class PingPayloadBody(TypedDict):
    pass


class PingPayload(Payload):
    body: PingPayloadBody


class PingReceiverPlugin(Plugin):
    callbacks: Set[PingCallback]
    _payload_verifier: TypedDictVerifier[PingPayload]

    def __init__(self, device: KdeConnectDevice):
        super().__init__(device)
        self.callbacks = set()
        self._payload_verifier = TypedDictVerifier[PingPayload]()

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> PingReceiverPlugin:
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return {"kdeconnect.ping"}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return set()

    async def handle_payload(self, payload: Payload) -> None:
        payload = self._payload_verifier.verify(payload)
        for callback in self.callbacks:
            await callback()

    def on_ping(self, callback: PingCallback) -> None:
        self.callbacks.add(callback)


class PingSenderPlugin(Plugin):
    async def handle_payload(self, payload: Payload) -> None:
        pass

    @classmethod
    def create_instance(cls, device: KdeConnectDevice) -> PingSenderPlugin:
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return set()

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return {"kdeconnect.ping"}
