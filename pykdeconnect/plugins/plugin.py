from abc import abstractmethod, ABC
from typing import Type, Sequence

from ..payloads import Payload


class Plugin(ABC):
    @classmethod
    @abstractmethod
    def get_incoming_payloads(cls) -> Sequence[Type[Payload]]:
        pass

    @classmethod
    @abstractmethod
    def get_outgoing_payloads(cls) -> Sequence[Type[Payload]]:
        pass
