from abc import ABCMeta, abstractmethod
from dataclasses import dataclass, field, KW_ONLY
from typing import List, Annotated, Any, TypeVar, overload, ClassVar, Type

from .dataclass_json import Flags, DataclassDecoder, DataclassEncoder


@dataclass  # type: ignore[misc]
class Payload:
    id: int

    @classmethod
    @property
    @abstractmethod
    def type(cls) -> str:
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
        tcpPort: Annotated[int | None, Flags.REMOVE_IF_NONE] = None

    body: Body
    type = "kdeconnect.identity"


@dataclass
class PairPayload(Payload):
    @dataclass
    class Body:
        pair: bool

    body: Body
    type = "kdeconnect.pair"


payloads: List[Type[Payload]] = [
    IdentityPayload,
    PairPayload
]

type_map = {
    payload.type: payload for payload in payloads
}


class PayloadEncoder:
    encoder: DataclassEncoder
    encoding: str

    def __init__(self, encoding='utf-8'):
        self.encoder = DataclassEncoder("type", type_map)
        self.encoding = encoding

    def encode(self, o: Any) -> bytes:
        # KDEConnect only recognized packages if they end with a newline
        return (self.encoder.encode(o) + '\n').encode(self.encoding)


class PayloadDecoder:
    decoder: DataclassDecoder
    encoding: str

    def __init__(self, encoding='utf-8'):
        self.decoder = DataclassDecoder("type", type_map)
        self.encoding = encoding

    T = TypeVar('T', bound=Payload)
    @overload
    def decode(self, b: bytes, type_: Type[T]) -> T: ...

    @overload
    def decode(self, b: bytes, type_: None = None) -> Any: ...

    def decode(self, b: bytes, type_: Type[T] | None = None) -> Any:
        return self.decoder.decode(b.decode(self.encoding), type_)


