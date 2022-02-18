from enum import Enum, IntEnum
from typing import List, Any, TYPE_CHECKING

from cryptography.x509 import Certificate
from typing_extensions import Self

from .const import KdeConnectDeviceType
from .protocols import DeviceProtocol
from .payloads import IdentityPayload
if TYPE_CHECKING:
    from .client import KdeConnectClient


class KdeConnectDevice:
    device_name: str
    device_id: str
    device_type: KdeConnectDeviceType
    incoming_capabilities: List[str]
    outgoing_capabilities: List[str]

    certificate: Certificate | None

    protocol: DeviceProtocol
    client: 'KdeConnectClient'

    wants_pairing: bool = False

    def __init__(self, device_name: str, device_id: str, device_type: KdeConnectDeviceType,
                 incoming_capabilities: List[str], outgoing_capabilities: List[str], client: 'KdeConnectClient'):
        self.device_name = device_name
        self.device_id = device_id
        self.device_type = device_type
        self.incoming_capabilities = list(incoming_capabilities)
        self.outgoing_capabilities = list(outgoing_capabilities)
        self.client = client

        self.protocol = DeviceProtocol(self, self.client)

        self.certificate = self.client.config.get_device_cert(self)

    def get_protocol(self) -> DeviceProtocol:
        return self.protocol

    def request_pair(self):
        self.protocol.send_pairing_packet(True)
        self.wants_pairing = True

    def unpair(self):
        self.protocol.send_pairing_packet(False)
        self.set_unpaired()

    def confirm_pair(self):
        self.protocol.send_pairing_packet(True)
        self.set_paired()

    def set_paired(self):
        self.certificate = self.protocol.get_certificate()
        self.client.config.trust_device(self)
        self.wants_pairing = False
        print("Paired device", self.device_name)

    def set_unpaired(self):
        self.certificate = None
        self.client.config.untrust_device(self)
        self.wants_pairing = False
        print("Unpaired device", self.device_name)

    @property
    def is_paired(self):
        return self.certificate is not None

    @classmethod
    def from_payload(cls, payload: IdentityPayload, client: 'KdeConnectClient') -> 'KdeConnectDevice':
        # TODO: Change return type to Self once mypy supports it
        return cls(payload.body.deviceName, payload.body.deviceId, KdeConnectDeviceType(payload.body.deviceType),
                   payload.body.incomingCapabilities, payload.body.outgoingCapabilities, client)
