from dataclasses import dataclass
from typing import Mapping, Sequence, Type

from .plugin import Plugin
from ..payloads import Payload


@dataclass
class PingPayload(Payload):
    @dataclass
    class Body:
        pass

    bool: Body
    type = "kdeconnect.ping"


class PingReceiverPlugin(Plugin):
    @classmethod
    def get_incoming_payloads(cls) -> Sequence[Type[Payload]]:
        return [PingPayload]

    @classmethod
    def get_outgoing_payloads(cls) -> Sequence[Type[Payload]]:
        return []


class PingSenderPlugin(Plugin):
    @classmethod
    def get_incoming_payloads(cls) -> Sequence[Type[Payload]]:
        return []

    @classmethod
    def get_outgoing_payloads(cls) -> Sequence[Type[Payload]]:
        return [PingPayload]
