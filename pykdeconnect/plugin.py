from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Set, Type

from pykdeconnect.payloads import Payload

if TYPE_CHECKING:
    from pykdeconnect.devices import KdeConnectDevice


class Plugin(ABC):
    device: 'KdeConnectDevice'

    def __init__(self, device: 'KdeConnectDevice'):
        self.device = device

    @classmethod
    @abstractmethod
    def get_incoming_payload_types(cls) -> Set[Type[Payload]]:
        pass

    @classmethod
    @abstractmethod
    def get_outgoing_payload_types(cls) -> Set[Type[Payload]]:
        pass

    @classmethod
    @abstractmethod
    def create_instance(cls, device: 'KdeConnectDevice'):
        pass

    @abstractmethod
    async def handle_payload(self, payload):
        pass
