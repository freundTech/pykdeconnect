from abc import abstractmethod
from dataclasses import dataclass, field
from typing import (
    Annotated, Any, Collection, List, Optional, Type, TypeVar, overload
)

from .dataclass_json import DataclassDecoder, DataclassEncoder, Flags
from .helpers import get_timestamp


# Mypy has a problem with abstract dataclasses
@dataclass  # type: ignore[misc]
class Payload:
    id: int = field(default_factory=get_timestamp, kw_only=True)
    payloadSize: Annotated[Optional[int], Flags.REMOVE_IF_NONE] = field(default=None, kw_only=True)
    payloadTransferInfo: Annotated[Optional[dict], Flags.REMOVE_IF_NONE] = field(default=None,
                                                                                 kw_only=True)

    @classmethod
    @abstractmethod
    def get_type(cls) -> str:
        pass


@dataclass
class IdentityPayload(Payload):
    @dataclass
    class Body:
        deviceId: str
        deviceName: str
        protocolVersion: int
        deviceType: str
        incomingCapabilities: List[str]
        outgoingCapabilities: List[str]
        tcpPort: Annotated[Optional[int], Flags.REMOVE_IF_NONE] = None

    body: Body

    @classmethod
    def get_type(cls) -> str:
        return "kdeconnect.identity"


@dataclass
class PairPayload(Payload):
    @dataclass
    class Body:
        pair: bool

    body: Body

    @classmethod
    def get_type(cls) -> str:
        return "kdeconnect.pair"


internal_payloads = {
    IdentityPayload.get_type(): IdentityPayload,
    PairPayload.get_type(): PairPayload
}


def get_payload_map(payloads: Collection[Type[Payload]]):
    payload_map = {
        p.get_type(): p for p in payloads
    }
    payload_map.update(internal_payloads)
    return payload_map


class PayloadEncoder:
    encoder: DataclassEncoder
    encoding: str

    def __init__(self, payloads: Collection[Type[Payload]], encoding='utf-8'):
        self.encoder = DataclassEncoder("type", get_payload_map(payloads))
        self.encoding = encoding

    def encode(self, o: Any) -> bytes:
        # KDEConnect only recognized packages if they end with a newline
        return (self.encoder.encode(o) + '\n').encode(self.encoding)


class PayloadDecoder:
    decoder: DataclassDecoder
    encoding: str

    def __init__(self, payloads: Collection[Type[Payload]], encoding='utf-8'):
        self.decoder = DataclassDecoder("type", get_payload_map(payloads), allow_dicts=True)
        self.encoding = encoding

    T = TypeVar('T', bound=Payload)
    @overload
    def decode(self, b: bytes, type_: Type[T]) -> T: ...

    @overload
    def decode(self, b: bytes, type_: None = None) -> Any: ...

    def decode(self, b: bytes, type_: Optional[Type[T]] = None) -> Any:
        return self.decoder.decode(b.decode(self.encoding), type_)
