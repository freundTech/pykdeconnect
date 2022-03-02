from typing import Awaitable, Callable, Set

from typing_extensions import TypedDict

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin
from pykdeconnect.vol_extra import verify_typed_dict

PingCallback = Callable[[], Awaitable[None]]


class PingPayloadBody(TypedDict):
    pass


class PingPayload(Payload):
    body: PingPayloadBody


class PingReceiverPlugin(Plugin):
    callbacks: Set[PingCallback]

    def __init__(self, device: KdeConnectDevice):
        super().__init__(device)
        self.callbacks = set()

    @classmethod
    def create_instance(cls, device: KdeConnectDevice):
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return {"kdeconnect.ping"}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return set()

    async def handle_payload(self, payload: Payload):
        payload = verify_typed_dict(payload, PingPayload)
        for callback in self.callbacks:
            await callback()

    def on_ping(self, callback: PingCallback):
        self.callbacks.add(callback)


class PingSenderPlugin(Plugin):
    async def handle_payload(self, payload):
        pass

    @classmethod
    def create_instance(cls, device: KdeConnectDevice):
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        return set()

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        return {"kdeconnect.ping"}
