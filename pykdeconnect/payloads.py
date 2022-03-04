from __future__ import annotations

import json
from typing import Any, List

from typing_extensions import NotRequired, TypedDict


class Payload(TypedDict):
    id: int | str  # KdeConnect on android sends int, but desktop sends str
    type: str
    payloadSize: NotRequired[int]
    payloadTransferInfo: NotRequired[dict]  # type: ignore


class AnyPayload(Payload):
    body: Any


class IdentityPayloadBody(TypedDict):
    deviceId: str
    deviceName: str
    protocolVersion: int
    deviceType: str
    incomingCapabilities: List[str]
    outgoingCapabilities: List[str]
    tcpPort: NotRequired[int]


class IdentityPayload(Payload):
    body: IdentityPayloadBody


class PairPayloadBody(TypedDict):
    pair: bool


class PairPayload(Payload):
    body: PairPayloadBody


internal_payloads = {
    "kdeconnect.identity": IdentityPayload,
    "kdeconnect.pair": PairPayload
}


def payload_to_bytes(payload: Payload) -> bytes:
    return json.dumps(payload).encode() + b'\n'


def bytes_to_payload(b: bytes | bytearray) -> object:
    return json.loads(b.decode())
