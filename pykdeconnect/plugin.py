from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Set

from pykdeconnect.payloads import Payload

if TYPE_CHECKING:
    from pykdeconnect.devices import KdeConnectDevice


class Plugin(ABC):
    device: KdeConnectDevice

    def __init__(self, device: KdeConnectDevice):
        self.device = device

    @classmethod
    @abstractmethod
    def get_incoming_payload_types(cls) -> Set[str]:
        pass

    @classmethod
    @abstractmethod
    def get_outgoing_payload_types(cls) -> Set[str]:
        pass

    @classmethod
    @abstractmethod
    def create_instance(cls, device: KdeConnectDevice):
        pass

    @abstractmethod
    async def handle_payload(self, payload: Payload):
        pass
