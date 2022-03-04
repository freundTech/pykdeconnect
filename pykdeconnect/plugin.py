from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Set

from .payloads import Payload

if TYPE_CHECKING:
    from .devices import KdeConnectDevice


class Plugin(ABC):
    device: KdeConnectDevice

    def __init__(self, device: KdeConnectDevice) -> None:
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
    def create_instance(cls, device: KdeConnectDevice) -> Plugin:
        pass

    @abstractmethod
    async def handle_payload(self, payload: Payload) -> None:
        pass
