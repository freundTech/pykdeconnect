from dataclasses import dataclass
from typing import Awaitable, Callable, Set, Type

from pykdeconnect.devices import KdeConnectDevice
from pykdeconnect.payloads import Payload
from pykdeconnect.plugin import Plugin

PingCallback = Callable[[], Awaitable[None]]


@dataclass
class PingPayload(Payload):
    @dataclass
    class Body:
        pass

    body: Body

    @classmethod
    def get_type(cls) -> str:
        return "kdeconnect.ping"


class PingReceiverPlugin(Plugin):
    callbacks: Set[PingCallback]

    def __init__(self, device: KdeConnectDevice):
        super().__init__(device)
        self.callbacks = set()

    @classmethod
    def create_instance(cls, device: KdeConnectDevice):
        return cls(device)

    @classmethod
    def get_incoming_payload_types(cls) -> Set[Type[Payload]]:
        return {PingPayload}

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[Type[Payload]]:
        return set()

    async def handle_payload(self, payload):
        assert isinstance(payload, PingPayload)
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
    def get_incoming_payload_types(cls) -> Set[Type[Payload]]:
        return set()

    @classmethod
    def get_outgoing_payload_types(cls) -> Set[Type[Payload]]:
        return {PingPayload}
