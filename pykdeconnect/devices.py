import asyncio
import logging
from asyncio import Future
from typing import List, TYPE_CHECKING, Optional

from cryptography.x509 import Certificate

from .const import KdeConnectDeviceType, PairingResult
from .helpers import async_timeout
from .payloads import IdentityPayload
from .protocols import DeviceProtocol

if TYPE_CHECKING:
    from .client import KdeConnectClient


logger = logging.getLogger(__name__)


class KdeConnectDevice:
    device_name: str
    device_id: str
    device_type: KdeConnectDeviceType
    incoming_capabilities: List[str]
    outgoing_capabilities: List[str]

    certificate: Optional[Certificate]

    protocol: DeviceProtocol
    client: 'KdeConnectClient'

    wants_pairing: bool = False
    pairing_future: Optional[Future[PairingResult]] = None

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

    async def pair(self) -> PairingResult:
        if self.is_paired:
            return PairingResult.ACCEPTED
        if self.pairing_future is None:
            self.request_pair()
            loop = asyncio.get_running_loop()
            self.pairing_future = loop.create_future()
        asyncio.create_task(async_timeout(self.pairing_future, PairingResult.TIMEOUT, 20))
        result = await self.pairing_future
        self.pairing_future = None
        return result

    def request_pair(self):
        self.protocol.send_pairing_packet(True)
        self.wants_pairing = True

    def unpair(self):
        self.protocol.send_pairing_packet(False)
        self.set_unpaired()

    def confirm_pair(self):
        self.protocol.send_pairing_packet(True)
        self.set_paired()

    def reject_pair(self):
        self.protocol.send_pairing_packet(False)

    def set_paired(self):
        self.certificate = self.protocol.get_certificate()
        self.client.config.trust_device(self)
        self.wants_pairing = False
        logger.debug(f'Paired device "{self.device_name}"')
        if self.pairing_future is not None:
            self.pairing_future.set_result(PairingResult.ACCEPTED)

    def set_unpaired(self):
        self.certificate = None
        self.client.config.untrust_device(self)
        self.wants_pairing = False
        logger.debug(f'Unpaired device "{self.device_name}"')
        if self.pairing_future is not None:
            self.pairing_future.set_result(PairingResult.REJECTED)

    @property
    def is_paired(self):
        return self.certificate is not None

    @classmethod
    def from_payload(cls, payload: IdentityPayload, client: 'KdeConnectClient') -> 'KdeConnectDevice':
        # TODO: Change return type to Self once mypy supports it
        return cls(payload.body.deviceName, payload.body.deviceId, KdeConnectDeviceType(payload.body.deviceType),
                   payload.body.incomingCapabilities, payload.body.outgoingCapabilities, client)
