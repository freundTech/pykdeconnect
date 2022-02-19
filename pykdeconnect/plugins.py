from abc import abstractmethod, ABC
from typing import Any


class Plugin(ABC):
    plugin_id: str

    @abstractmethod
    def is_incoming(self) -> bool:
        pass

    @abstractmethod
    def is_outgoing(self) -> bool:
        pass

    @abstractmethod
    def on_message(self, payload: Any):
        pass
